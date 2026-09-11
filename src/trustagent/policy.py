from __future__ import annotations

from trustagent.models import AgentRecord, DelegationGrant
from trustagent.registry import AgentRegistry


class CapabilityPolicy:
    def __init__(self, trusted_resources: frozenset[str]) -> None:
        self.trusted_resources = trusted_resources

    def authorized(self, record: AgentRecord, capability: str) -> bool:
        return capability in record.capabilities

    def resource_trusted(self, resource: str) -> bool:
        return resource in self.trusted_resources

    def delegation_monotonic(
        self,
        registry: AgentRegistry,
        grant: DelegationGrant,
        requested: str,
    ) -> bool:
        issuer = registry.get(grant.issuer)
        if issuer is None:
            return False
        if not grant.scope.issubset(issuer.capabilities):
            return False
        if requested not in grant.scope:
            return False
        return True
