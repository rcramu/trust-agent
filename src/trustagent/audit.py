from __future__ import annotations

from dataclasses import dataclass

from trustagent.models import AuthorizationRequest, Decision, utcnow


@dataclass
class AuditEvent:
    agent_id: str
    resource: str
    capability: str
    outcome: str
    reason: str
    ats: float | None
    mode: str
    recorded_at: str


class AuditLog:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, request: AuthorizationRequest, decision: Decision) -> AuditEvent:
        event = AuditEvent(
            agent_id=request.agent_id,
            resource=request.resource,
            capability=request.capability,
            outcome=decision.outcome.value,
            reason=decision.reason,
            ats=decision.ats,
            mode=decision.mode,
            recorded_at=utcnow().isoformat(),
        )
        self.events.append(event)
        return event
