from __future__ import annotations

import time
from enum import Enum
from typing import Any

import jwt

from trustagent.ats import (
    AtsThresholds,
    AtsWeights,
    authorization_score,
    behavior_score,
    context_score,
    credential_score,
    identity_score,
    resource_score,
)
from trustagent.audit import AuditLog
from trustagent.cards import declared_capabilities, verify_card
from trustagent.keys import JWS_ALG, KeyStore
from trustagent.models import (
    AgentStatus,
    AuthorizationRequest,
    Channel,
    Decision,
    Outcome,
    utcnow,
)
from trustagent.policy import CapabilityPolicy
from trustagent.registry import AgentRegistry
from trustagent.tokens import LabIdentityProvider


class EnforcementMode(str, Enum):
    B1 = "B1"
    B2 = "B2"
    B3 = "B3"
    B3_STATIC = "B3_STATIC"
    B3_NO_BEHAVIOR = "B3_NO_BEHAVIOR"
    B3_NO_RESOURCE = "B3_NO_RESOURCE"


class TrustAgentGateway:
    def __init__(
        self,
        registry: AgentRegistry,
        idp: LabIdentityProvider,
        policy: CapabilityPolicy,
        keys: KeyStore,
        *,
        mode: EnforcementMode = EnforcementMode.B3,
        weights: AtsWeights | None = None,
        thresholds: AtsThresholds | None = None,
    ) -> None:
        self.registry = registry
        self.idp = idp
        self.policy = policy
        self.keys = keys
        self.mode = mode
        self.weights = weights or AtsWeights()
        self.thresholds = thresholds or AtsThresholds()
        self.audit = AuditLog()
        self._seen_jti: set[str] = set()
        self._revoked_grants: set[str] = set()

    def authorize(self, request: AuthorizationRequest) -> Decision:
        started = time.perf_counter()
        decision = self._decide(request)
        elapsed = (time.perf_counter() - started) * 1000.0
        stamped = Decision(
            outcome=decision.outcome,
            reason=decision.reason,
            ats=decision.ats,
            latency_ms=elapsed,
            mode=self.mode.value,
            dimensions=decision.dimensions,
            phases_ms=decision.phases_ms,
        )
        self.audit.record(request, stamped)
        return stamped

    def _decide(self, request: AuthorizationRequest) -> Decision:
        if self.mode is EnforcementMode.B1:
            return Decision(Outcome.ALLOW, "B1: no agent-specific checks", None, 0.0, self.mode.value)

        started = time.perf_counter()
        token_claims, token_error = self._validate_token(request)
        token_ms = (time.perf_counter() - started) * 1000.0
        if token_error:
            return Decision(Outcome.DENY, token_error, None, 0.0, self.mode.value, phases_ms={"token_ms": token_ms})

        if self.mode is EnforcementMode.B2:
            return Decision(Outcome.ALLOW, "B2: token valid", None, 0.0, self.mode.value, phases_ms={"token_ms": token_ms})

        decision = self._trustagent(request, token_claims)
        phases = dict(decision.phases_ms)
        phases["token_ms"] = token_ms
        return Decision(
            decision.outcome,
            decision.reason,
            decision.ats,
            0.0,
            self.mode.value,
            decision.dimensions,
            phases,
        )

    def _validate_token(self, request: AuthorizationRequest) -> tuple[dict[str, Any] | None, str | None]:
        try:
            claims = self.idp.decode(request.token, audience=request.audience)
        except jwt.ExpiredSignatureError:
            return None, "credential expired"
        except jwt.InvalidAudienceError:
            return None, "token audience mismatch"
        except jwt.PyJWTError as exc:
            return None, f"credential invalid: {exc.__class__.__name__}"
        if claims.get("sub") != request.agent_id:
            return None, "token subject does not match agent"
        return claims, None

    def _trustagent(self, request: AuthorizationRequest, token_claims: dict[str, Any]) -> Decision:
        record = self.registry.get(request.agent_id)
        if record is None:
            return Decision(Outcome.DENY, "agent is not registered", 0.0, 0.0, self.mode.value)

        status = self.registry.status(request.agent_id)
        if status is AgentStatus.REVOKED:
            return Decision(Outcome.DENY, "agent is revoked", 0.0, 0.0, self.mode.value)
        if status is AgentStatus.SUSPENDED:
            return Decision(Outcome.DENY, "agent is suspended", 0.0, 0.0, self.mode.value)
        if status is AgentStatus.RETIRED:
            return Decision(Outcome.DENY, "agent is retired", 0.0, 0.0, self.mode.value)
        if status is AgentStatus.EXPIRED:
            return Decision(Outcome.DENY, "agent identity expired", 0.0, 0.0, self.mode.value)

        phases: dict[str, float] = {}
        card_ok = True
        if request.channel is Channel.A2A or request.card_jws:
            started = time.perf_counter()
            card_ok, card_reason = self._verify_card(request, record)
            phases["card_ms"] = (time.perf_counter() - started) * 1000.0
            if not card_ok:
                return Decision(Outcome.DENY, card_reason, 0.0, 0.0, self.mode.value, phases_ms=phases)

        started = time.perf_counter()
        if request.delegation is not None:
            if not self._verify_delegation(request):
                return Decision(Outcome.DENY, "delegation is not monotonic or not verifiable", 0.0, 0.0, self.mode.value, phases_ms=phases)
        elif not self.policy.authorized(record, request.capability):
            return Decision(Outcome.DENY, "capability is not authorized", 0.0, 0.0, self.mode.value, phases_ms=phases)
        phases["policy_ms"] = (time.perf_counter() - started) * 1000.0

        if request.channel is Channel.A2A:
            peer_status = self.registry.status(request.resource)
            if peer_status is not AgentStatus.ACTIVE:
                return Decision(Outcome.DENY, "A2A peer is not an active registered agent", 0.0, 0.0, self.mode.value, phases_ms=phases)
        elif not self.policy.resource_trusted(request.resource):
            return Decision(Outcome.DENY, "resource is untrusted", 0.0, 0.0, self.mode.value, phases_ms=phases)

        jti = token_claims.get("jti")
        if isinstance(jti, str):
            if jti in self._seen_jti:
                return Decision(Outcome.DENY, "token replay detected", 0.0, 0.0, self.mode.value, phases_ms=phases)
            self._seen_jti.add(jti)

        if self.mode is EnforcementMode.B3_STATIC:
            return Decision(Outcome.ALLOW, "static policy passed", None, 0.0, self.mode.value, phases_ms=phases)

        weights = self.weights
        if self.mode is EnforcementMode.B3_NO_BEHAVIOR:
            weights = weights.without("behavior")
        elif self.mode is EnforcementMode.B3_NO_RESOURCE:
            weights = weights.without("resource")

        exp = int(token_claims["exp"])
        iat = int(token_claims.get("iat", exp))
        now_ts = int(utcnow().timestamp())
        lifetime = max(1, exp - iat)
        remaining = max(0.0, (exp - now_ts) / lifetime)

        started = time.perf_counter()
        dims = {
            "I": identity_score(True and card_ok),
            "C": credential_score(valid=True, remaining_fraction=remaining, audience_ok=True),
            "A": authorization_score(True),
            "B": behavior_score(record, request, self.audit),
            "R": resource_score(True),
            "X": context_score(request),
        }
        ats = weights.combine(dims["I"], dims["C"], dims["A"], dims["B"], dims["R"], dims["X"])
        phases["ats_ms"] = (time.perf_counter() - started) * 1000.0
        outcome, reason = self._band(ats)
        return Decision(outcome, reason, ats, 0.0, self.mode.value, dims, phases)

    def _verify_card(self, request: AuthorizationRequest, record) -> tuple[bool, str]:
        if not request.card_jws:
            return False, "A2A request missing Agent Card"
        try:
            payload = verify_card(request.card_jws, self.registry)
        except Exception as exc:
            return False, f"Agent Card verification failed: {exc}"
        if payload.get("agent_id") != request.agent_id:
            return False, "Agent Card agent_id mismatch"
        declared = declared_capabilities(payload)
        if not declared.issubset(record.capabilities):
            return False, "declared capabilities exceed registry"
        return True, ""

    def _verify_delegation(self, request: AuthorizationRequest) -> bool:
        grant = request.delegation
        if grant is None:
            return False
        if grant.subject != request.agent_id:
            return False
        issuer_key = self.registry.public_key(grant.issuer)
        if issuer_key is None:
            return False
        try:
            claims = jwt.decode(grant.compact_jws, issuer_key, algorithms=[JWS_ALG])
        except jwt.PyJWTError:
            return False
        if claims.get("iss") != grant.issuer or claims.get("sub") != grant.subject:
            return False
        grant_jti = claims.get("jti")
        if isinstance(grant_jti, str) and grant_jti in self._revoked_grants:
            return False
        return self.policy.delegation_monotonic(self.registry, grant, request.capability)

    def revoke_delegation(self, grant_jti: str) -> None:
        self._revoked_grants.add(grant_jti)

    def _band(self, ats: float) -> tuple[Outcome, str]:
        if ats >= self.thresholds.allow:
            return Outcome.ALLOW, "ATS allow"
        if ats >= self.thresholds.restrict:
            return Outcome.ALLOW_WITH_RESTRICTIONS, "ATS restrict"
        if ats >= self.thresholds.verify:
            return Outcome.ADDITIONAL_VERIFICATION, "ATS additional verification"
        if ats >= self.thresholds.approval:
            return Outcome.REQUIRE_HUMAN_APPROVAL, "ATS requires human approval"
        return Outcome.DENY, "ATS deny"
