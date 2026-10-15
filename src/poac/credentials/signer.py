"""Where the issuer's private key lives.

Ed25519 (the receipt's primary signature, ``alg: Ed25519``, RFC 8037/9864):
``LocalKeySigner`` — an Ed25519 JWK in memory (tests, dev, single box).
``KmsSigner``      — AWS KMS ``ECC_NIST_EDWARDS25519`` key; the private key
                     never leaves the HSM, this process only sees signatures.

ML-DSA-65 (post-quantum second signature, ``alg: ML-DSA-65``, RFC 9964,
JWK ``kty: AKP``), used only for dual-signed receipts:
``LocalMlDsaSigner`` / ``KmsMlDsaSigner`` (KMS ``ML_DSA_65``).

All expose the same things the issuer needs: ``alg``, ``kid``, the public
JWK for ``/.well-known/jwks.json``, and ``sign(signing_input) -> bytes``.
Serialisation is assembled in ``issuer.py`` so the wire format is identical
whichever backend is behind it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric import mldsa
from joserfc.jwk import OKPKey

ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")  # DER SubjectPublicKeyInfo, 44 bytes total
# DER SubjectPublicKeyInfo prefix for id-ml-dsa-65 (2.16.840.1.101.3.4.3.18); raw key is 1952 bytes
MLDSA65_SPKI_PREFIX = bytes.fromhex("308207b2300b0609608648016503040312038207a100")
MLDSA65_PUB_LEN = 1952
MLDSA65_SIG_LEN = 3309
ALG_ED25519 = "Ed25519"
ALG_MLDSA65 = "ML-DSA-65"


class SignerError(RuntimeError):
    """Signing backend unavailable or misconfigured. Never produces a receipt."""


class Signer(Protocol):
    @property
    def alg(self) -> str: ...
    @property
    def kid(self) -> str: ...
    def public_jwk(self) -> dict[str, Any]: ...
    def sign(self, signing_input: bytes) -> bytes: ...


def akp_jwk(pub_raw: bytes) -> dict[str, Any]:
    """RFC 9964 JWK for an ML-DSA-65 public key, with its RFC 7638 thumbprint
    as ``kid`` (required members for ``AKP``: ``alg``, ``kty``, ``pub``)."""
    if len(pub_raw) != MLDSA65_PUB_LEN:
        raise SignerError(f"ML-DSA-65 public key must be {MLDSA65_PUB_LEN} bytes, got {len(pub_raw)}")
    jwk = {"kty": "AKP", "alg": ALG_MLDSA65, "pub": _b64url(pub_raw)}
    canonical = json.dumps({k: jwk[k] for k in ("alg", "kty", "pub")}, separators=(",", ":"))
    jwk["kid"] = _b64url(hashlib.sha256(canonical.encode("ascii")).digest())
    jwk["use"] = "sig"
    return jwk


def mldsa65_public_key(jwk: dict[str, Any]) -> mldsa.MLDSA65PublicKey:
    """Parse an ``AKP``/``ML-DSA-65`` JWK into a verifying key."""
    if jwk.get("kty") != "AKP" or jwk.get("alg") != ALG_MLDSA65 or "priv" in jwk:
        raise ValueError("not a public ML-DSA-65 AKP JWK")
    pub = jwk.get("pub")
    if not isinstance(pub, str):
        raise ValueError("AKP JWK lacks pub")
    return mldsa.MLDSA65PublicKey.from_public_bytes(_b64url_decode(pub))


class LocalKeySigner:
    alg = ALG_ED25519

    def __init__(self, key: OKPKey):
        if key.curve_name != "Ed25519":
            raise SignerError("issuer key must be Ed25519")
        if not key.is_private:
            raise SignerError("issuer key must include the private part")
        self._key = key
        self._kid = key.thumbprint()

    @property
    def kid(self) -> str:
        return self._kid

    def public_jwk(self) -> dict[str, Any]:
        jwk = self._key.as_dict(private=False)
        jwk["kid"] = self._kid
        return jwk

    def sign(self, signing_input: bytes) -> bytes:
        return self._key.private_key.sign(signing_input)


class LocalMlDsaSigner:
    alg = ALG_MLDSA65

    def __init__(self, key: mldsa.MLDSA65PrivateKey):
        self._key = key
        self._jwk = akp_jwk(key.public_key().public_bytes_raw())

    @classmethod
    def generate(cls) -> "LocalMlDsaSigner":
        return cls(mldsa.MLDSA65PrivateKey.generate())

    @property
    def kid(self) -> str:
        return self._jwk["kid"]

    def public_jwk(self) -> dict[str, Any]:
        return dict(self._jwk)

    def sign(self, signing_input: bytes) -> bytes:
        return self._key.sign(signing_input)


class _KmsBase:
    """Shared KMS plumbing: lazy boto3 client, GetPublicKey at construction,
    Sign with ``MessageType=RAW``. Any client failure is a ``SignerError``
    (config error at startup, 503 at issue time) — never a bad receipt."""

    key_spec: str
    signing_algorithm: str
    sig_len: int
    alg: str

    def __init__(self, key_id: str, client: Any | None = None, region: str | None = None):
        self._key_id = key_id
        if client is None:
            try:
                import boto3  # optional dependency: pip install "poac[kms]"
            except ImportError as exc:
                raise SignerError("boto3 is required for KMS signers (pip install 'poac[kms]')") from exc
            client = boto3.client("kms", region_name=region or os.environ.get("POAC_KMS_REGION"))
        self._client = client
        try:
            info = client.get_public_key(KeyId=key_id)
        except Exception as exc:  # noqa: BLE001 - any client failure is a config error here
            raise SignerError(f"KMS GetPublicKey failed for {key_id}: {exc}") from exc
        if info.get("KeySpec") != self.key_spec:
            raise SignerError(f"KMS key {key_id} is {info.get('KeySpec')}, need {self.key_spec}")
        self._jwk = self._jwk_from_spki(bytes(info["PublicKey"]))

    def _jwk_from_spki(self, der: bytes) -> dict[str, Any]:  # pragma: no cover - abstract
        raise NotImplementedError

    @property
    def kid(self) -> str:
        return self._jwk["kid"]

    @property
    def key_id(self) -> str:
        return self._key_id

    def public_jwk(self) -> dict[str, Any]:
        return dict(self._jwk)

    def sign(self, signing_input: bytes) -> bytes:
        try:
            out = self._client.sign(
                KeyId=self._key_id,
                Message=signing_input,
                MessageType="RAW",
                SigningAlgorithm=self.signing_algorithm,
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as 503 by the API, never a bad receipt
            raise SignerError(f"KMS Sign failed: {exc.__class__.__name__}") from exc
        sig = bytes(out["Signature"])
        if len(sig) != self.sig_len:
            raise SignerError(f"KMS returned a {len(sig)}-byte signature, expected {self.sig_len}")
        return sig


class KmsSigner(_KmsBase):
    """AWS KMS-backed Ed25519 signer (PureEdDSA: ``ED25519_SHA_512`` + ``RAW``).

    ``client`` is a boto3 KMS client or anything with the same
    ``get_public_key``/``sign`` shape (tests use a fake). Credentials and
    region come from the standard AWS environment unless a client is given.
    """

    key_spec = "ECC_NIST_EDWARDS25519"
    signing_algorithm = "ED25519_SHA_512"
    sig_len = 64
    alg = ALG_ED25519

    def _jwk_from_spki(self, der: bytes) -> dict[str, Any]:
        if len(der) != 44 or not der.startswith(ED25519_SPKI_PREFIX):
            raise SignerError("unexpected Ed25519 SubjectPublicKeyInfo from KMS")
        public = OKPKey.import_key(
            {"kty": "OKP", "crv": "Ed25519", "x": _b64url(der[12:]), "alg": ALG_ED25519, "use": "sig"}
        )
        jwk = public.as_dict(private=False)
        jwk["kid"] = public.thumbprint()
        return jwk


class KmsMlDsaSigner(_KmsBase):
    """AWS KMS-backed ML-DSA-65 signer (``ML_DSA_SHAKE_256`` over the raw
    JWS signing input, i.e. pure ML-DSA with empty context, as RFC 9964)."""

    key_spec = "ML_DSA_65"
    signing_algorithm = "ML_DSA_SHAKE_256"
    sig_len = MLDSA65_SIG_LEN
    alg = ALG_MLDSA65

    def _jwk_from_spki(self, der: bytes) -> dict[str, Any]:
        if not der.startswith(MLDSA65_SPKI_PREFIX) or len(der) != len(MLDSA65_SPKI_PREFIX) + MLDSA65_PUB_LEN:
            raise SignerError("unexpected ML-DSA-65 SubjectPublicKeyInfo from KMS")
        return akp_jwk(der[len(MLDSA65_SPKI_PREFIX):])


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
