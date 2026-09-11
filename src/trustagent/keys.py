from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

# ES256: ECDSA on P-256 with SHA-256. Private keys stay in memory for the lab
# process. They are never written to the repository or to source.
CURVE = ec.SECP256R1()
JWS_ALG = "ES256"


class KeyStore:
    """Ephemeral P-256 keypairs indexed by a logical name (agent id or 'idp')."""

    def __init__(self) -> None:
        self._private: dict[str, EllipticCurvePrivateKey] = {}

    def generate(self, name: str) -> EllipticCurvePublicKey:
        if name in self._private:
            raise ValueError(f"key already exists: {name}")
        key = ec.generate_private_key(CURVE)
        self._private[name] = key
        return key.public_key()

    def rotate(self, name: str) -> EllipticCurvePublicKey:
        self._private.pop(name, None)
        return self.generate(name)

    def private(self, name: str) -> EllipticCurvePrivateKey:
        try:
            return self._private[name]
        except KeyError as exc:
            raise KeyError(f"unknown key: {name}") from exc

    def public(self, name: str) -> EllipticCurvePublicKey:
        return self.private(name).public_key()

    def has(self, name: str) -> bool:
        return name in self._private
