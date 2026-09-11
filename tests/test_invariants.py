from trustagent.gateway import EnforcementMode
from trustagent.lab import HELPER_AGENT, INCIDENT_READ, SECURITY_AGENT, LabWorld
from trustagent.models import AuthorizationRequest, Channel, Outcome


def test_p1_unregistered_signer_denied():
    lab = LabWorld()
    gateway = lab.gateway(EnforcementMode.B3)
    decision = gateway.authorize(
        AuthorizationRequest(
            agent_id=SECURITY_AGENT,
            resource=HELPER_AGENT,
            capability="incident.read",
            token=lab.token(SECURITY_AGENT),
            channel=Channel.A2A,
            card_jws=lab.rogue_card(SECURITY_AGENT, ["incident.read"]),
        )
    )
    assert decision.outcome is Outcome.DENY


def test_p2_unknown_capability_denied():
    lab = LabWorld()
    gateway = lab.gateway(EnforcementMode.B3)
    decision = gateway.authorize(
        AuthorizationRequest(
            agent_id=SECURITY_AGENT,
            resource=INCIDENT_READ,
            capability="database.admin",
            token=lab.token(SECURITY_AGENT),
            channel=Channel.MCP,
        )
    )
    assert decision.outcome is Outcome.DENY


def test_p3_delegation_cannot_amplify():
    lab = LabWorld()
    gateway = lab.gateway(EnforcementMode.B3)
    grant = lab.delegation(SECURITY_AGENT, HELPER_AGENT, frozenset({"incident.delete"}))
    decision = gateway.authorize(
        AuthorizationRequest(
            agent_id=HELPER_AGENT,
            resource="mcp://enterprise/tools/incident.delete",
            capability="incident.delete",
            token=lab.token(HELPER_AGENT),
            channel=Channel.MCP,
            delegation=grant,
        )
    )
    assert decision.outcome is Outcome.DENY
    assert "delegation" in decision.reason


def test_p3_monotonic_read_delegation_allowed():
    lab = LabWorld()
    gateway = lab.gateway(EnforcementMode.B3)
    grant = lab.delegation(SECURITY_AGENT, HELPER_AGENT, frozenset({"incident.read"}))
    decision = gateway.authorize(
        AuthorizationRequest(
            agent_id=HELPER_AGENT,
            resource=INCIDENT_READ,
            capability="incident.read",
            token=lab.token(HELPER_AGENT),
            channel=Channel.MCP,
            delegation=grant,
        )
    )
    assert decision.autonomously_permitted


def test_p4_revoked_agent_denied():
    lab = LabWorld()
    token = lab.token(SECURITY_AGENT)
    lab.registry.revoke(SECURITY_AGENT)
    gateway = lab.gateway(EnforcementMode.B3)
    decision = gateway.authorize(
        AuthorizationRequest(
            agent_id=SECURITY_AGENT,
            resource=INCIDENT_READ,
            capability="incident.read",
            token=token,
            channel=Channel.MCP,
        )
    )
    assert decision.outcome is Outcome.DENY
    assert "revoked" in decision.reason


def test_legitimate_mcp_allowed_on_b3():
    lab = LabWorld()
    decision = lab.gateway(EnforcementMode.B3).authorize(lab.legitimate_mcp())
    assert decision.autonomously_permitted
    assert decision.ats is not None and decision.ats >= 75
