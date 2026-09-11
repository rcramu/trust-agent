from __future__ import annotations

import json
from typing import Any

import jwt

from trustagent.keys import JWS_ALG, KeyStore
from trustagent.registry import AgentRegistry


def card_payload(
    agent_id: str,
    *,
    provider: str,
    capabilities: list[str],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "agent_id": agent_id,
        "provider": provider,
        "capabilities": sorted(capabilities),
    }
    if extra:
        body.update(extra)
    return body


def sign_card(keys: KeyStore, agent_id: str, payload: dict[str, Any]) -> str:
    return jwt.encode(payload, keys.private(agent_id), algorithm=JWS_ALG)


def decode_unverified(card_jws: str) -> dict[str, Any]:
    return jwt.decode(card_jws, options={"verify_signature": False})


def verify_card(card_jws: str, registry: AgentRegistry) -> dict[str, Any]:
    unverified = decode_unverified(card_jws)
    agent_id = unverified.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id:
        raise ValueError("Agent Card missing agent_id")
    public_key = registry.public_key(agent_id)
    if public_key is None:
        raise ValueError("Agent Card signer is not registered")
    return jwt.decode(card_jws, public_key, algorithms=[JWS_ALG])


def declared_capabilities(payload: dict[str, Any]) -> frozenset[str]:
    caps = payload.get("capabilities", [])
    if not isinstance(caps, list) or not all(isinstance(c, str) for c in caps):
        raise ValueError("Agent Card capabilities must be a list of strings")
    return frozenset(caps)


def tamper_declared_capabilities(card_jws: str, capabilities: list[str]) -> str:
    """Return a compact JWS whose payload was altered after signing.

    Used as a defensive fixture: the gateway must reject it. This is not a
    signing oracle and does not produce a valid signature.
    """
    header_b64, _payload_b64, signature_b64 = card_jws.split(".")
    mutated = decode_unverified(card_jws)
    mutated["capabilities"] = sorted(capabilities)
    new_payload = jwt.utils.base64url_encode(
        json.dumps(mutated, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).decode("ascii")
    return f"{header_b64}.{new_payload}.{signature_b64}"
