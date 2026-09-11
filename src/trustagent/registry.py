from __future__ import annotations

from datetime import datetime

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from trustagent.models import AgentRecord, AgentStatus, utcnow


class AgentRegistry:
    def __init__(self) -> None:
        self._records: dict[str, AgentRecord] = {}
        self._public_keys: dict[str, EllipticCurvePublicKey] = {}

    def register(self, record: AgentRecord, public_key: EllipticCurvePublicKey) -> None:
        self._records[record.agent_id] = record
        self._public_keys[record.agent_id] = public_key

    def get(self, agent_id: str) -> AgentRecord | None:
        return self._records.get(agent_id)

    def public_key(self, agent_id: str) -> EllipticCurvePublicKey | None:
        return self._public_keys.get(agent_id)

    def revoke(self, agent_id: str) -> None:
        record = self._records[agent_id]
        self._records[agent_id] = AgentRecord(
            agent_id=record.agent_id,
            provider=record.provider,
            status=AgentStatus.REVOKED,
            capabilities=record.capabilities,
            purpose=record.purpose,
            owner=record.owner,
            risk_class=record.risk_class,
            expires_at=record.expires_at,
            resource_trust=record.resource_trust,
        )

    def status(self, agent_id: str, now: datetime | None = None) -> AgentStatus | None:
        record = self.get(agent_id)
        if record is None:
            return None
        moment = now or utcnow()
        if record.status is AgentStatus.REVOKED:
            return AgentStatus.REVOKED
        if record.expires_at is not None and record.expires_at <= moment:
            return AgentStatus.EXPIRED
        return record.status
