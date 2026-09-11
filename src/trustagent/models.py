from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class AgentStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    EXPIRED = "expired"
    RETIRED = "retired"


class Outcome(str, Enum):
    ALLOW = "ALLOW"
    ALLOW_WITH_RESTRICTIONS = "ALLOW_WITH_RESTRICTIONS"
    ADDITIONAL_VERIFICATION = "ADDITIONAL_VERIFICATION"
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"
    DENY = "DENY"


class Channel(str, Enum):
    A2A = "a2a"
    MCP = "mcp"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class AgentRecord:
    agent_id: str
    provider: str
    status: AgentStatus
    capabilities: frozenset[str]
    purpose: str
    owner: str
    risk_class: str = "medium"
    expires_at: datetime | None = None
    resource_trust: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class DelegationGrant:
    issuer: str
    subject: str
    scope: frozenset[str]
    compact_jws: str


@dataclass
class AuthorizationRequest:
    agent_id: str
    resource: str
    capability: str
    token: str
    channel: Channel = Channel.MCP
    audience: str = "mcp://enterprise/tools"
    card_jws: str | None = None
    delegation: DelegationGrant | None = None
    context: dict[str, Any] = field(default_factory=dict)
    replay_of: str | None = None


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    reason: str
    ats: float | None
    latency_ms: float
    mode: str
    dimensions: dict[str, float] = field(default_factory=dict)
    phases_ms: dict[str, float] = field(default_factory=dict)

    @property
    def autonomously_permitted(self) -> bool:
        return self.outcome in {Outcome.ALLOW, Outcome.ALLOW_WITH_RESTRICTIONS}
