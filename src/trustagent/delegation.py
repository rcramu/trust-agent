from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import jwt

from trustagent.keys import JWS_ALG, KeyStore
from trustagent.models import DelegationGrant, utcnow


def issue_delegation(
    keys: KeyStore,
    issuer: str,
    subject: str,
    scope: frozenset[str],
    *,
    ttl_seconds: int = 120,
) -> DelegationGrant:
    now = utcnow()
    compact = jwt.encode(
        {
            "iss": issuer,
            "sub": subject,
            "scope": sorted(scope),
            "jti": str(uuid4()),
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        },
        keys.private(issuer),
        algorithm=JWS_ALG,
    )
    return DelegationGrant(
        issuer=issuer,
        subject=subject,
        scope=scope,
        compact_jws=compact,
    )
