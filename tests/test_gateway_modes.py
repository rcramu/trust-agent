from datetime import timedelta

import jwt

from trustagent.ats import AtsThresholds
from trustagent.cards import card_payload, sign_card
from trustagent.gateway import EnforcementMode, TrustAgentGateway
from trustagent.lab import (
    ADMIN_WIPE,
    HELPER_AGENT,
    INCIDENT_READ,
    SECURITY_AGENT,
    LabWorld,
)
from trustagent.models import (
    AgentRecord,
    AgentStatus,
    AuthorizationRequest,
    Channel,
    DelegationGrant,
    Outcome,
    utcnow,
)


def test_b1_allows_without_a_token():
    lab = LabWorld()
    request = lab.legitimate_mcp()
    request.token = "not-a-jwt"
    decision = lab.gateway(EnforcementMode.B1).authorize(request)
    assert decision.outcome is Outcome.ALLOW


def test_b2_allows_valid_token_and_rejects_bad_audience():
    lab = LabWorld()
    gateway = lab.gateway(EnforcementMode.B2)
    assert gateway.authorize(lab.legitimate_mcp()).outcome is Outcome.ALLOW
    bad = lab.legitimate_mcp()
    bad.token = lab.token(SECURITY_AGENT, audience="mcp://other")
    assert "audience" in gateway.authorize(bad).reason


def test_b2_rejects_expired_and_garbage_and_subject_mismatch():
    lab = LabWorld()
    gateway = lab.gateway(EnforcementMode.B2)
    expired = lab.legitimate_mcp()
    expired.token = lab.token(SECURITY_AGENT, ttl_seconds=-20)
    assert gateway.authorize(expired).reason == "credential expired"
    garbage = lab.legitimate_mcp()
    garbage.token = "aaa.bbb.ccc"
    assert gateway.authorize(garbage).reason.startswith("credential invalid")
    mismatch = lab.legitimate_mcp()
    mismatch.agent_id = HELPER_AGENT
    assert "subject" in gateway.authorize(mismatch).reason


def test_unregistered_and_expired_identity_denied():
    lab = LabWorld()
    unknown = AuthorizationRequest(
        agent_id="agent://nobody",
        resource=INCIDENT_READ,
        capability="incident.read",
        token=lab.idp.issue("agent://nobody"),
        channel=Channel.MCP,
    )
    assert lab.gateway(EnforcementMode.B3).authorize(unknown).reason == "agent is not registered"

    record = lab.registry.get(SECURITY_AGENT)
    lab.registry.register(
        AgentRecord(
            agent_id=record.agent_id,
            provider=record.provider,
            status=AgentStatus.ACTIVE,
            capabilities=record.capabilities,
            purpose=record.purpose,
            owner=record.owner,
            expires_at=utcnow() - timedelta(hours=1),
        ),
        lab.registry.public_key(SECURITY_AGENT),
    )
    decision = lab.gateway(EnforcementMode.B3).authorize(lab.legitimate_mcp())
    assert "expired" in decision.reason


def test_untrusted_mcp_resource_and_unknown_a2a_peer():
    lab = LabWorld()
    gateway = lab.gateway(EnforcementMode.B3)
    mcp = AuthorizationRequest(
        agent_id=SECURITY_AGENT,
        resource=ADMIN_WIPE,
        capability="incident.read",
        token=lab.token(SECURITY_AGENT),
        channel=Channel.MCP,
    )
    assert gateway.authorize(mcp).reason == "resource is untrusted"
    a2a = lab.legitimate_a2a()
    a2a.resource = "agent://enterprise/missing"
    assert "peer" in gateway.authorize(a2a).reason


def test_replay_and_static_and_ablation_modes():
    lab = LabWorld()
    request = lab.legitimate_mcp()
    full = lab.gateway(EnforcementMode.B3)
    assert full.authorize(request).autonomously_permitted
    replay = AuthorizationRequest(
        agent_id=request.agent_id,
        resource=request.resource,
        capability=request.capability,
        token=request.token,
        channel=Channel.MCP,
    )
    assert full.authorize(replay).reason == "token replay detected"

    static = lab.gateway(EnforcementMode.B3_STATIC)
    assert static.authorize(lab.legitimate_mcp()).reason == "static policy passed"
    no_behavior = lab.gateway(EnforcementMode.B3_NO_BEHAVIOR)
    assert no_behavior.authorize(lab.legitimate_mcp()).autonomously_permitted
    no_resource = lab.gateway(EnforcementMode.B3_NO_RESOURCE)
    assert no_resource.authorize(lab.legitimate_mcp()).autonomously_permitted


def test_card_paths_and_ats_bands():
    lab = LabWorld()
    gateway = lab.gateway(EnforcementMode.B3)
    missing = lab.legitimate_a2a()
    missing.card_jws = None
    assert "missing Agent Card" in gateway.authorize(missing).reason

    helper_card = lab.card(HELPER_AGENT)
    swapped = lab.legitimate_a2a()
    swapped.card_jws = helper_card
    assert "agent_id mismatch" in gateway.authorize(swapped).reason

    inflated = lab.legitimate_a2a()
    inflated.card_jws = lab.card(SECURITY_AGENT, ["incident.read", "incident.delete"])
    assert "exceed registry" in gateway.authorize(inflated).reason

    tight = TrustAgentGateway(
        lab.registry,
        lab.idp,
        lab.policy,
        lab.keys,
        mode=EnforcementMode.B3,
        thresholds=AtsThresholds(allow=99.0, restrict=98.0, approval=97.0),
    )
    allowed = TrustAgentGateway(
        lab.registry,
        lab.idp,
        lab.policy,
        lab.keys,
        mode=EnforcementMode.B3,
        thresholds=AtsThresholds(allow=50.0, restrict=40.0, approval=20.0),
    )
    deny = tight.authorize(
        AuthorizationRequest(
            agent_id=SECURITY_AGENT,
            resource=INCIDENT_READ,
            capability="incident.read",
            token=lab.token(SECURITY_AGENT),
            channel=Channel.MCP,
            context={"behavior_deviation": 1.0, "context_risk": 1.0},
        )
    )
    assert deny.outcome is Outcome.DENY
    assert allowed.authorize(lab.legitimate_mcp()).outcome is Outcome.ALLOW


def test_delegation_failure_modes():
    lab = LabWorld()
    gateway = lab.gateway(EnforcementMode.B3)
    good = lab.delegation(SECURITY_AGENT, HELPER_AGENT, frozenset({"incident.read"}))

    wrong_subject = AuthorizationRequest(
        agent_id=SECURITY_AGENT,
        resource=INCIDENT_READ,
        capability="incident.read",
        token=lab.token(SECURITY_AGENT),
        channel=Channel.MCP,
        delegation=good,
    )
    assert "delegation" in gateway.authorize(wrong_subject).reason

    unknown_issuer = DelegationGrant(
        issuer="agent://missing",
        subject=HELPER_AGENT,
        scope=frozenset({"incident.read"}),
        compact_jws=good.compact_jws,
    )
    req = AuthorizationRequest(
        agent_id=HELPER_AGENT,
        resource=INCIDENT_READ,
        capability="incident.read",
        token=lab.token(HELPER_AGENT),
        channel=Channel.MCP,
        delegation=unknown_issuer,
    )
    assert "delegation" in gateway.authorize(req).reason

    broken = DelegationGrant(
        issuer=SECURITY_AGENT,
        subject=HELPER_AGENT,
        scope=frozenset({"incident.read"}),
        compact_jws="not.a.jws",
    )
    req.delegation = broken
    assert "delegation" in gateway.authorize(req).reason

    other = sign_card(
        lab.keys,
        SECURITY_AGENT,
        card_payload(SECURITY_AGENT, provider="enterprise", capabilities=["incident.read"]),
    )
    mismatched = DelegationGrant(
        issuer=SECURITY_AGENT,
        subject=HELPER_AGENT,
        scope=frozenset({"incident.read"}),
        compact_jws=other,
    )
    req.delegation = mismatched
    assert "delegation" in gateway.authorize(req).reason

    assert gateway._verify_delegation(
        AuthorizationRequest(
            SECURITY_AGENT,
            INCIDENT_READ,
            "incident.read",
            lab.token(SECURITY_AGENT),
        )
    ) is False


def test_non_string_jti_skips_replay_cache(monkeypatch):
    lab = LabWorld()
    gateway = lab.gateway(EnforcementMode.B3)
    real_decode = lab.idp.decode

    def decode(token, *, audience, leeway_seconds=0):
        claims = real_decode(token, audience=audience, leeway_seconds=leeway_seconds)
        claims["jti"] = 17
        return claims

    monkeypatch.setattr(lab.idp, "decode", decode)
    request = lab.legitimate_mcp()
    assert gateway.authorize(request).autonomously_permitted
    assert gateway.authorize(request).autonomously_permitted


def test_ats_requires_human_approval_on_high_deviation():
    lab = LabWorld()
    decision = lab.gateway(EnforcementMode.B3).authorize(
        AuthorizationRequest(
            agent_id=SECURITY_AGENT,
            resource=INCIDENT_READ,
            capability="incident.read",
            token=lab.token(SECURITY_AGENT),
            channel=Channel.MCP,
            context={"behavior_deviation": 1.0, "context_risk": 0.2},
        )
    )
    assert decision.outcome is Outcome.REQUIRE_HUMAN_APPROVAL


def test_ats_additional_verification_band():
    lab = LabWorld()
    decision = lab.gateway(EnforcementMode.B3).authorize(
        AuthorizationRequest(
            agent_id=SECURITY_AGENT,
            resource=INCIDENT_READ,
            capability="incident.read",
            token=lab.token(SECURITY_AGENT),
            channel=Channel.MCP,
            context={"behavior_deviation": 0.7, "context_risk": 0.2},
        )
    )
    assert decision.outcome is Outcome.ADDITIONAL_VERIFICATION
    assert not decision.autonomously_permitted


def test_suspended_retired_and_revoked_delegation():
    lab = LabWorld()
    gateway = lab.gateway(EnforcementMode.B3)
    lab.registry.suspend(SECURITY_AGENT)
    assert "suspended" in gateway.authorize(lab.legitimate_mcp()).reason
    lab.registry.retire(SECURITY_AGENT)
    assert "retired" in gateway.authorize(lab.legitimate_mcp()).reason

    lab = LabWorld()
    gateway = lab.gateway(EnforcementMode.B3)
    grant = lab.delegation(SECURITY_AGENT, HELPER_AGENT, frozenset({"incident.read"}))
    claims = jwt.decode(grant.compact_jws, options={"verify_signature": False})
    gateway.revoke_delegation(claims["jti"])
    denied = gateway.authorize(
        AuthorizationRequest(
            agent_id=HELPER_AGENT,
            resource=INCIDENT_READ,
            capability="incident.read",
            token=lab.token(HELPER_AGENT),
            channel=Channel.MCP,
            delegation=grant,
        )
    )
    assert "delegation" in denied.reason
