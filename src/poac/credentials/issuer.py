"""Receipt issuance: Ed25519 JWS over measured facts, holder-bound via cnf.jkt.

Built on joserfc (maintained JOSE implementation); no custom cryptography.
The claim layout is documented in docs/protocol.md section 6.1. The module
boundary is adapter-shaped so an RFC 9901 SD-JWT+KB backend can be swapped
in for interoperability testing later without touching the orchestrator.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Callable

from joserfc.jwk import OKPKey
from joserfc.jws import JWSRegistry

from poac.credentials.signer import LocalKeySigner, Signer
from poac.protocol.models import (
    PROTOCOL_VERSION,
    SUITE_VERSION,
    CapabilityTier,
    HolderJwk,
    IdentityTier,
)

RECEIPT_TYP = "poac+jwt"
# RFC 9864 fully-specified algorithm (replaces the polymorphic "EdDSA").
ALLOWED_ALG = "Ed25519"

# The explicit registry pins the one accepted algorithm for sign and verify.
EDDSA_REGISTRY = JWSRegistry(algorithms=[ALLOWED_ALG])


def holder_thumbprint(holder_jwk: HolderJwk) -> str:
    """RFC 7638 thumbprint of the committed holder key."""
    key = OKPKey.import_key(
        {"kty": holder_jwk.kty, "crv": holder_jwk.crv, "x": holder_jwk.x}
    )
    return key.thumbprint()


class ReceiptIssuer:
    """Builds and signs receipts. ``key`` may be an Ed25519 ``OKPKey`` (kept
    for compatibility; wrapped in ``LocalKeySigner``) or any ``Signer``
    (e.g. ``KmsSigner``). ``previous_keys`` are public JWKs that stay in the
    JWKS so receipts signed before a key switch verify until they expire."""

    def __init__(
        self,
        key: OKPKey | Signer,
        issuer_url: str = "urn:poac:prototype",
        now: Callable[[], int] | None = None,
        previous_keys: list[dict] | None = None,
    ):
        if isinstance(key, OKPKey):
            if key.curve_name != "Ed25519":
                raise ValueError("issuer key must be Ed25519")
            key = LocalKeySigner(key)
        self._signer: Signer = key
        self._issuer_url = issuer_url
        self._now = now or (lambda: int(time.time()))
        self._previous: list[dict] = []
        for jwk in previous_keys or []:
            pub = OKPKey.import_key(jwk)
            d = pub.as_dict(private=False)  # never republish a private part
            d["kid"] = d.get("kid") or pub.thumbprint()
            if d["kid"] != self._signer.kid:
                self._previous.append(d)

    @classmethod
    def generate(cls, issuer_url: str = "urn:poac:prototype") -> "ReceiptIssuer":
        key = OKPKey.generate_key("Ed25519", {"alg": ALLOWED_ALG, "use": "sig"})
        return cls(key, issuer_url)

    @property
    def issuer_url(self) -> str:
        return self._issuer_url

    @property
    def signer(self) -> Signer:
        return self._signer

    def jwks(self) -> dict:
        """Public JWKS for /.well-known/jwks.json: current key first, then
        any previous keys still inside their switchover window."""
        return {"keys": [self._signer.public_jwk(), *self._previous]}

    def issue(
        self,
        session_id: str,
        capability_tier: CapabilityTier,
        identity_tier: IdentityTier,
        families: list[str],
        latencies_ms: list[int],
        rounds_total: int,
        receipt_ttl_s: int,
        holder_jwk: HolderJwk | None,
    ) -> str:
        now = self._now()
        claims: dict = {
            "iss": self._issuer_url,
            "sub": "poac-session",
            "jti": session_id,
            "iat": now,
            "exp": now + receipt_ttl_s,
            "poac": {
                "version": PROTOCOL_VERSION,
                "suite_version": SUITE_VERSION,
                "capability_tier": capability_tier.value,
                "identity_tier": identity_tier.value,
                "families": families,
                "rounds_passed": len(latencies_ms),
                "rounds_total": rounds_total,
                "latency_ms": latencies_ms,
            },
        }
        if holder_jwk is not None:
            claims["cnf"] = {"jkt": holder_thumbprint(holder_jwk)}
        header = {
            "alg": ALLOWED_ALG,
            "typ": RECEIPT_TYP,
            "kid": self._signer.kid,
        }
        # Compact JWS assembled here so KMS- and local-signed receipts are
        # byte-for-byte the same shape (RFC 7515 §5.1, JSON with no spaces).
        signing_input = _b64url(_json(header)) + "." + _b64url(_json(claims))
        signature = self._signer.sign(signing_input.encode("ascii"))
        return signing_input + "." + _b64url(signature)


def _json(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
