"""Receipt issuance: Ed25519 JWS over measured facts, holder-bound via cnf.jkt.

Two serialisations of the same claims:

* ``compact`` (default) — RFC 7515 §7.1 compact JWS, ``alg: Ed25519``. Every
  JWT library verifies it.
* ``json-dual`` (on request, when the issuer has an ML-DSA-65 signer) —
  RFC 7515 §7.2.1 general JSON serialisation with two signatures over the
  same payload: Ed25519 and ML-DSA-65 (RFC 9964). Post-quantum readiness:
  a relying party can demand the PQ signature today, and the receipt still
  verifies classically for everyone else.

Built on joserfc / cryptography; no custom cryptography. The claim layout
is documented in docs/protocol.md section 6.1.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Callable, Literal

from joserfc.jwk import OKPKey
from joserfc.jws import JWSRegistry

from poac.credentials.signer import ALG_MLDSA65, LocalKeySigner, LocalMlDsaSigner, Signer
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

ReceiptFormat = Literal["compact", "json-dual"]
RECEIPT_FORMATS: tuple[str, ...] = ("compact", "json-dual")


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
    JWKS so receipts signed before a key switch verify until they expire.
    ``pq_signer`` (ML-DSA-65) enables the ``json-dual`` receipt format."""

    def __init__(
        self,
        key: OKPKey | Signer,
        issuer_url: str = "urn:poac:prototype",
        now: Callable[[], int] | None = None,
        previous_keys: list[dict] | None = None,
        pq_signer: Signer | None = None,
    ):
        if isinstance(key, OKPKey):
            if key.curve_name != "Ed25519":
                raise ValueError("issuer key must be Ed25519")
            key = LocalKeySigner(key)
        self._signer: Signer = key
        if pq_signer is not None and pq_signer.alg != ALG_MLDSA65:
            raise ValueError(f"pq_signer must be {ALG_MLDSA65}, got {pq_signer.alg}")
        self._pq: Signer | None = pq_signer
        self._issuer_url = issuer_url
        self._now = now or (lambda: int(time.time()))
        from poac.credentials.keyring import public_jwk_with_kid  # local: keyring imports signer

        current = {self._signer.kid} | ({self._pq.kid} if self._pq else set())
        # validated public-only copies (never republish a private part), with
        # an optional retire_at after which jwks() stops publishing them
        self._previous: list[dict] = [
            d for d in (public_jwk_with_kid(j) for j in previous_keys or []) if d["kid"] not in current
        ]

    @classmethod
    def generate(cls, issuer_url: str = "urn:poac:prototype", pq: bool = True) -> "ReceiptIssuer":
        """Fresh in-memory issuer (dev/tests). ``pq=True`` also generates an
        ML-DSA-65 key so ``json-dual`` receipts are available."""
        key = OKPKey.generate_key("Ed25519", {"alg": ALLOWED_ALG, "use": "sig"})
        return cls(key, issuer_url, pq_signer=LocalMlDsaSigner.generate() if pq else None)

    @property
    def issuer_url(self) -> str:
        return self._issuer_url

    @property
    def signer(self) -> Signer:
        return self._signer

    @property
    def pq_signer(self) -> Signer | None:
        return self._pq

    @property
    def receipt_formats(self) -> list[str]:
        return ["compact", "json-dual"] if self._pq else ["compact"]

    def jwks(self) -> dict:
        """Public JWKS for /.well-known/jwks.json: current Ed25519 key first,
        then the ML-DSA-65 key if any, then previous keys still inside
        their switchover window."""
        keys = [self._signer.public_jwk()]
        if self._pq is not None:
            keys.append(self._pq.public_jwk())
        now = self._now()
        for k in self._previous:
            if k.get("retire_at") is None or k["retire_at"] > now:
                keys.append({kk: v for kk, v in k.items() if kk != "retire_at"})
        return {"keys": keys}

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
        receipt_format: ReceiptFormat = "compact",
    ) -> str:
        if receipt_format not in RECEIPT_FORMATS:
            raise ValueError(f"unknown receipt format {receipt_format!r}")
        if receipt_format == "json-dual" and self._pq is None:
            raise ValueError("json-dual receipts need an ML-DSA-65 pq_signer")
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
        payload = _b64url(_json(claims))
        # JWS assembled here so KMS- and local-signed receipts are
        # byte-for-byte the same shape (RFC 7515 §5.1, JSON with no spaces).
        protected, signature = self._sign_with(self._signer, payload)
        if receipt_format == "compact":
            return f"{protected}.{payload}.{signature}"
        assert self._pq is not None
        pq_protected, pq_signature = self._sign_with(self._pq, payload)
        general = {
            "payload": payload,
            "signatures": [
                {"protected": protected, "signature": signature},
                {"protected": pq_protected, "signature": pq_signature},
            ],
        }
        return _json(general).decode("ascii")

    @staticmethod
    def _sign_with(signer: Signer, payload: str) -> tuple[str, str]:
        header = {"alg": signer.alg, "typ": RECEIPT_TYP, "kid": signer.kid}
        protected = _b64url(_json(header))
        signature = signer.sign(f"{protected}.{payload}".encode("ascii"))
        return protected, _b64url(signature)


def _json(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
