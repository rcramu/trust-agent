import pytest

from trustagent.cards import card_payload, declared_capabilities, sign_card, verify_card
from trustagent.channels import A2AGateway, McpGateway
from trustagent.gateway import EnforcementMode
from trustagent.keys import KeyStore
from trustagent.lab import HELPER_AGENT, INCIDENT_READ, SECURITY_AGENT, LabWorld
from trustagent.models import DelegationGrant
from trustagent.policy import CapabilityPolicy
from trustagent.tokens import pkce_challenge, pkce_verifier


def test_card_payload_extra_and_verify_errors():
    lab = LabWorld()
    payload = card_payload(
        SECURITY_AGENT,
        provider="enterprise",
        capabilities=["incident.read"],
        extra={"skill": "triage"},
    )
    assert payload["skill"] == "triage"
    compact = sign_card(lab.keys, SECURITY_AGENT, payload)
    assert verify_card(compact, lab.registry)["skill"] == "triage"

    with pytest.raises(ValueError, match="missing agent_id"):
        verify_card(sign_card(lab.keys, SECURITY_AGENT, {"capabilities": []}), lab.registry)
    with pytest.raises(ValueError, match="not registered"):
        verify_card(
            sign_card(
                lab.keys,
                SECURITY_AGENT,
                card_payload("agent://ghost", provider="x", capabilities=["incident.read"]),
            ),
            lab.registry,
        )
    with pytest.raises(ValueError, match="list of strings"):
        declared_capabilities({"capabilities": [1, 2]})
    assert declared_capabilities({}) == frozenset()


def test_keystore_duplicate_and_missing():
    keys = KeyStore()
    keys.generate("one")
    with pytest.raises(ValueError, match="already exists"):
        keys.generate("one")
    with pytest.raises(KeyError, match="unknown key"):
        keys.private("missing")


def test_channels_wrap_authorize():
    lab = LabWorld()
    gateway = lab.gateway(EnforcementMode.B3)
    mcp = McpGateway(gateway)
    a2a = A2AGateway(lab.gateway(EnforcementMode.B3))
    mcp_decision = mcp.invoke(lab.legitimate_mcp())
    a2a_decision = a2a.send(lab.legitimate_a2a())
    assert mcp_decision.autonomously_permitted
    assert a2a_decision.autonomously_permitted


def test_policy_and_registry_edges():
    lab = LabWorld()
    policy = CapabilityPolicy(frozenset({INCIDENT_READ}))
    grant = DelegationGrant(
        issuer="agent://missing",
        subject=HELPER_AGENT,
        scope=frozenset({"incident.read"}),
        compact_jws="x",
    )
    assert policy.delegation_monotonic(lab.registry, grant, "incident.read") is False
    owned = lab.delegation(SECURITY_AGENT, HELPER_AGENT, frozenset({"incident.read"}))
    assert policy.delegation_monotonic(lab.registry, owned, "incident.delete") is False
    assert lab.registry.status("agent://missing") is None


def test_token_extra_claims_and_unknown_code():
    lab = LabWorld()
    token = lab.idp.issue(SECURITY_AGENT, extra={"role": "lab"})
    assert lab.idp.decode(token, audience="mcp://enterprise/tools")["role"] == "lab"
    with pytest.raises(ValueError, match="unknown or reused"):
        lab.idp.exchange_code("no-such-code", pkce_verifier())
    verifier = pkce_verifier()
    code = lab.idp.begin_authorization_code(SECURITY_AGENT, pkce_challenge(verifier))
    lab.idp.exchange_code(code, verifier)
    with pytest.raises(ValueError, match="unknown or reused"):
        lab.idp.exchange_code(code, verifier)
