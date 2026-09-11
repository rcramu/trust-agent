import pytest

from trustagent.ats import (
    AtsWeights,
    authorization_score,
    behavior_score,
    context_score,
    credential_score,
    identity_score,
    resource_score,
)
from trustagent.gateway import EnforcementMode
from trustagent.lab import SECURITY_AGENT, LabWorld
from trustagent.models import AuthorizationRequest, Channel


def test_weights_without_behavior_renormalizes():
    trimmed = AtsWeights().without("behavior")
    assert trimmed.behavior == 0.0
    assert trimmed.identity > AtsWeights().identity
    total = (
        trimmed.identity
        + trimmed.credential
        + trimmed.authorization
        + trimmed.behavior
        + trimmed.resource
        + trimmed.context
    )
    assert total == pytest.approx(1.0)


def test_weights_without_all_positive_terms_fails():
    with pytest.raises(ValueError, match="positive weight"):
        AtsWeights().without("identity", "credential", "authorization", "behavior", "resource")


def test_combine_clamps():
    weights = AtsWeights(identity=1.0, credential=0, authorization=0, behavior=0, resource=0, context=0)
    assert weights.combine(200, 0, 0, 0, 0, 0) == 100.0
    assert weights.combine(0, 0, 0, 0, 0, 200) == 0.0


def test_score_helpers():
    assert identity_score(False) == 0.0
    assert authorization_score(False) == 0.0
    assert resource_score(False) == 10.0
    assert credential_score(valid=False, remaining_fraction=1.0, audience_ok=True) == 0.0
    assert credential_score(valid=True, remaining_fraction=0.2, audience_ok=False) == 75.0
    assert context_score(AuthorizationRequest("a", "r", "c", "t", context={"context_risk": 2.0})) == 100.0


def test_behavior_score_purpose_and_clamp():
    lab = LabWorld()
    record = lab.registry.get(SECURITY_AGENT)
    off_purpose = AuthorizationRequest(
        SECURITY_AGENT,
        "r",
        "payroll.export",
        "t",
        channel=Channel.MCP,
    )
    assert behavior_score(record, off_purpose) == 40.0
    injected = AuthorizationRequest(
        SECURITY_AGENT,
        "r",
        "incident.read",
        "t",
        context={"behavior_deviation": 5.0},
    )
    assert behavior_score(record, injected) == 0.0


def test_behavior_score_uses_recent_audit_denies():
    lab = LabWorld()
    record = lab.registry.get(SECURITY_AGENT)
    gateway = lab.gateway(EnforcementMode.B3)
    denied = AuthorizationRequest(
        SECURITY_AGENT,
        "r",
        "database.admin",
        lab.token(SECURITY_AGENT),
        channel=Channel.MCP,
    )
    gateway.authorize(denied)
    on_purpose = AuthorizationRequest(
        SECURITY_AGENT,
        "r",
        "incident.read",
        "t",
        channel=Channel.MCP,
    )
    assert behavior_score(record, on_purpose, gateway.audit) == 50.0
