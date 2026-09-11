import pytest

from trustagent.cards import tamper_declared_capabilities, verify_card
from trustagent.lab import SECURITY_AGENT, LabWorld
from trustagent.tokens import pkce_challenge, pkce_verifier


def test_pkce_round_trip():
    lab = LabWorld()
    verifier = pkce_verifier()
    challenge = pkce_challenge(verifier)
    code = lab.idp.begin_authorization_code(SECURITY_AGENT, challenge, scope="incident.read")
    token = lab.idp.exchange_code(code, verifier)
    claims = lab.idp.decode(token, audience="mcp://enterprise/tools")
    assert claims["sub"] == SECURITY_AGENT


def test_pkce_wrong_verifier_rejected():
    lab = LabWorld()
    verifier = pkce_verifier()
    code = lab.idp.begin_authorization_code(SECURITY_AGENT, pkce_challenge(verifier))
    with pytest.raises(ValueError, match="PKCE"):
        lab.idp.exchange_code(code, pkce_verifier())


def test_honest_card_verifies():
    lab = LabWorld()
    payload = verify_card(lab.card(SECURITY_AGENT), lab.registry)
    assert payload["agent_id"] == SECURITY_AGENT


def test_tampered_card_fails_verify():
    lab = LabWorld()
    tampered = tamper_declared_capabilities(lab.card(SECURITY_AGENT), ["incident.delete"])
    with pytest.raises(Exception):
        verify_card(tampered, lab.registry)
