from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import timedelta
from typing import Any
from uuid import uuid4

import jwt

from trustagent.keys import JWS_ALG, KeyStore
from trustagent.models import utcnow

IDP_KEY_NAME = "idp"
DEFAULT_AUDIENCE = "mcp://enterprise/tools"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def pkce_verifier() -> str:
    return _b64url(secrets.token_bytes(32))


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return _b64url(digest)


class LabIdentityProvider:
    """Lab OAuth 2.1-style token issuer. Signs access tokens with ES256.

    PKCE (S256) is required when a token is issued from an authorization code.
    Direct issue() is for evaluation fixtures that already represent a completed
    token grant. No client secrets are stored in source.
    """

    def __init__(self, keys: KeyStore) -> None:
        if not keys.has(IDP_KEY_NAME):
            keys.generate(IDP_KEY_NAME)
        self._keys = keys
        self._codes: dict[str, dict[str, Any]] = {}

    def issue(
        self,
        subject: str,
        *,
        audience: str = DEFAULT_AUDIENCE,
        scope: str = "",
        ttl_seconds: int = 300,
        extra: dict[str, Any] | None = None,
    ) -> str:
        now = utcnow()
        claims: dict[str, Any] = {
            "iss": "https://lab.trustagent.example/idp",
            "sub": subject,
            "aud": audience,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
            "jti": str(uuid4()),
            "scope": scope,
        }
        if extra:
            claims.update(extra)
        return jwt.encode(
            claims,
            self._keys.private(IDP_KEY_NAME),
            algorithm=JWS_ALG,
        )

    def begin_authorization_code(
        self,
        subject: str,
        challenge: str,
        *,
        audience: str = DEFAULT_AUDIENCE,
        scope: str = "",
        ttl_seconds: int = 300,
    ) -> str:
        code = _b64url(secrets.token_bytes(32))
        self._codes[code] = {
            "subject": subject,
            "challenge": challenge,
            "audience": audience,
            "scope": scope,
            "ttl_seconds": ttl_seconds,
        }
        return code

    def exchange_code(self, code: str, verifier: str) -> str:
        record = self._codes.pop(code, None)
        if record is None:
            raise ValueError("unknown or reused authorization code")
        if pkce_challenge(verifier) != record["challenge"]:
            raise ValueError("PKCE verifier does not match challenge")
        return self.issue(
            record["subject"],
            audience=record["audience"],
            scope=record["scope"],
            ttl_seconds=record["ttl_seconds"],
        )

    def decode(self, token: str, *, audience: str, leeway_seconds: int = 0) -> dict[str, Any]:
        return jwt.decode(
            token,
            self._keys.public(IDP_KEY_NAME),
            algorithms=[JWS_ALG],
            audience=audience,
            issuer="https://lab.trustagent.example/idp",
            leeway=leeway_seconds,
        )
