from __future__ import annotations

from trustagent.cards import card_payload, sign_card
from trustagent.delegation import issue_delegation
from trustagent.gateway import EnforcementMode, TrustAgentGateway
from trustagent.keys import KeyStore
from trustagent.models import AgentRecord, AgentStatus, Channel
from trustagent.policy import CapabilityPolicy
from trustagent.registry import AgentRegistry
from trustagent.tokens import DEFAULT_AUDIENCE, LabIdentityProvider

SECURITY_AGENT = "agent://enterprise/security-agent"
HELPER_AGENT = "agent://enterprise/helper-agent"
ROGUE_AGENT = "agent://rogue/impostor"

INCIDENT_READ = "mcp://enterprise/tools/incident.read"
INCIDENT_DELETE = "mcp://enterprise/tools/incident.delete"
THREAT_SEARCH = "mcp://enterprise/tools/threat.search"
ADMIN_WIPE = "mcp://enterprise/tools/admin.wipe"

TRUSTED_RESOURCES = frozenset({INCIDENT_READ, INCIDENT_DELETE, THREAT_SEARCH})


class LabWorld:
    """In-memory A2A + MCP lab. Keys exist only for the process lifetime."""

    def __init__(self) -> None:
        self.keys = KeyStore()
        self.registry = AgentRegistry()
        self.idp = LabIdentityProvider(self.keys)
        self.policy = CapabilityPolicy(TRUSTED_RESOURCES)
        self._register_agents()

    def _register_agents(self) -> None:
        for agent_id, capabilities, purpose in (
            (
                SECURITY_AGENT,
                frozenset({"incident.read", "incident.analyze", "threat.search"}),
                "incident threat",
            ),
            (
                HELPER_AGENT,
                frozenset({"incident.read"}),
                "incident",
            ),
        ):
            public = self.keys.generate(agent_id)
            self.registry.register(
                AgentRecord(
                    agent_id=agent_id,
                    provider="enterprise",
                    status=AgentStatus.ACTIVE,
                    capabilities=capabilities,
                    purpose=purpose,
                    owner="security-platform",
                    resource_trust=TRUSTED_RESOURCES,
                ),
                public,
            )
        self.keys.generate(ROGUE_AGENT)

    def gateway(self, mode: EnforcementMode) -> TrustAgentGateway:
        return TrustAgentGateway(
            self.registry,
            self.idp,
            self.policy,
            self.keys,
            mode=mode,
        )

    def token(self, agent_id: str, *, ttl_seconds: int = 300, audience: str = DEFAULT_AUDIENCE) -> str:
        record = self.registry.get(agent_id)
        scope = " ".join(sorted(record.capabilities)) if record else ""
        return self.idp.issue(agent_id, audience=audience, scope=scope, ttl_seconds=ttl_seconds)

    def card(self, agent_id: str, capabilities: list[str] | None = None) -> str:
        record = self.registry.get(agent_id)
        caps = capabilities if capabilities is not None else sorted(record.capabilities) if record else []
        provider = record.provider if record else "unknown"
        return sign_card(self.keys, agent_id, card_payload(agent_id, provider=provider, capabilities=caps))

    def rogue_card(self, claimed_id: str, capabilities: list[str]) -> str:
        return sign_card(
            self.keys,
            ROGUE_AGENT,
            card_payload(claimed_id, provider="enterprise", capabilities=capabilities),
        )

    def delegation(self, issuer: str, subject: str, scope: frozenset[str]):
        return issue_delegation(self.keys, issuer, subject, scope)

    def legitimate_mcp(self):
        from trustagent.models import AuthorizationRequest

        return AuthorizationRequest(
            agent_id=SECURITY_AGENT,
            resource=INCIDENT_READ,
            capability="incident.read",
            token=self.token(SECURITY_AGENT),
            channel=Channel.MCP,
        )

    def legitimate_a2a(self):
        from trustagent.models import AuthorizationRequest

        return AuthorizationRequest(
            agent_id=SECURITY_AGENT,
            resource=HELPER_AGENT,
            capability="incident.read",
            token=self.token(SECURITY_AGENT),
            channel=Channel.A2A,
            card_jws=self.card(SECURITY_AGENT),
        )
