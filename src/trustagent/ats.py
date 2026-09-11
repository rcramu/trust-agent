from __future__ import annotations

from dataclasses import dataclass

from trustagent.models import AgentRecord, AuthorizationRequest, Outcome


@dataclass(frozen=True)
class AtsWeights:
    identity: float = 0.20
    credential: float = 0.10
    authorization: float = 0.20
    behavior: float = 0.25
    resource: float = 0.10
    context: float = 0.15

    def without(self, *names: str) -> AtsWeights:
        data = {
            "identity": self.identity,
            "credential": self.credential,
            "authorization": self.authorization,
            "behavior": self.behavior,
            "resource": self.resource,
            "context": self.context,
        }
        for name in names:
            data[name] = 0.0
        positive = sum(v for k, v in data.items() if k != "context")
        if positive <= 0:
            raise ValueError("ATS needs at least one positive weight")
        scale = (1.0 - data["context"]) / positive
        for key in ("identity", "credential", "authorization", "behavior", "resource"):
            data[key] *= scale
        return AtsWeights(**data)

    def combine(
        self,
        identity: float,
        credential: float,
        authorization: float,
        behavior: float,
        resource: float,
        context: float,
    ) -> float:
        raw = (
            self.identity * identity
            + self.credential * credential
            + self.authorization * authorization
            + self.behavior * behavior
            + self.resource * resource
            - self.context * context
        )
        return max(0.0, min(100.0, raw))


@dataclass(frozen=True)
class AtsThresholds:
    allow: float = 90.0
    restrict: float = 75.0
    verify: float = 60.0
    approval: float = 40.0


def identity_score(verified: bool) -> float:
    return 100.0 if verified else 0.0


def credential_score(*, valid: bool, remaining_fraction: float, audience_ok: bool) -> float:
    if not valid:
        return 0.0
    score = 70.0
    if remaining_fraction >= 0.5:
        score += 15.0
    elif remaining_fraction > 0:
        score += 5.0
    if audience_ok:
        score += 15.0
    return score


def authorization_score(authorized: bool) -> float:
    return 100.0 if authorized else 0.0


def behavior_score(record: AgentRecord, request: AuthorizationRequest, audit: object | None = None) -> float:
    injected = request.context.get("behavior_deviation")
    if injected is not None:
        return 100.0 * (1.0 - max(0.0, min(1.0, float(injected))))
    base = 100.0 if request.capability.split(".")[0] in record.purpose else 40.0
    events = getattr(audit, "events", None)
    if events:
        recent = [e for e in events[-8:] if e.agent_id == record.agent_id]
        if recent:
            withheld = sum(
                1
                for e in recent
                if e.outcome
                in {
                    Outcome.DENY.value,
                    Outcome.REQUIRE_HUMAN_APPROVAL.value,
                    Outcome.ADDITIONAL_VERIFICATION.value,
                }
            )
            base *= 1.0 - 0.5 * (withheld / len(recent))
    return base


def resource_score(trusted: bool) -> float:
    return 100.0 if trusted else 10.0


def context_score(request: AuthorizationRequest) -> float:
    risk = request.context.get("context_risk", 0.0)
    return 100.0 * max(0.0, min(1.0, float(risk)))
