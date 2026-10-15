"""Where the issuer's private key lives.

``LocalKeySigner`` — an Ed25519 JWK in memory (tests, dev, single box).
``KmsSigner``      — AWS KMS ``ECC_NIST_EDWARDS25519`` key; the private key
                     never leaves the HSM, this process only sees signatures.

Both expose the same three things the issuer needs: a ``kid``, the public
JWK for ``/.well-known/jwks.json``, and ``sign(signing_input) -> 64 bytes``.
The JWS compact serialisation is assembled in ``issuer.py`` so the wire
format is identical whichever signer is behind it.
"""

from __future__ import annotations

import os
from typing import Any, Protocol

from joserfc.jwk import OKPKey

ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")  # DER SubjectPublicKeyInfo, 44 bytes total


class SignerError(RuntimeError):
    """Signing backend unavailable or misconfigured. Never produces a receipt."""


class Signer(Protocol):
    @property
    def kid(self) -> str: ...
    def public_jwk(self) -> dict[str, Any]: ...
    def sign(self, signing_input: bytes) -> bytes: ...


class LocalKeySigner:
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


class KmsSigner:
    """AWS KMS-backed Ed25519 signer (PureEdDSA: ``ED25519_SHA_512`` + ``RAW``).

    ``client`` is a boto3 KMS client or anything with the same
    ``get_public_key``/``sign`` shape (tests use a fake). Credentials and
    region come from the standard AWS environment unless a client is given.
    """

    def __init__(self, key_id: str, client: Any | None = None, region: str | None = None):
        self._key_id = key_id
        if client is None:
            try:
                import boto3  # optional dependency: pip install "poac[kms]"
            except ImportError as exc:
                raise SignerError("boto3 is required for KmsSigner (pip install 'poac[kms]')") from exc
            client = boto3.client("kms", region_name=region or os.environ.get("POAC_KMS_REGION"))
        self._client = client
        try:
            info = client.get_public_key(KeyId=key_id)
        except Exception as exc:  # noqa: BLE001 - any client failure is a config error here
            raise SignerError(f"KMS GetPublicKey failed for {key_id}: {exc}") from exc
        if info.get("KeySpec") != "ECC_NIST_EDWARDS25519":
            raise SignerError(f"KMS key {key_id} is {info.get('KeySpec')}, need ECC_NIST_EDWARDS25519")
        der = bytes(info["PublicKey"])
        if len(der) != 44 or not der.startswith(ED25519_SPKI_PREFIX):
            raise SignerError("unexpected Ed25519 SubjectPublicKeyInfo from KMS")
        self._public = OKPKey.import_key(
            {"kty": "OKP", "crv": "Ed25519", "x": _b64url(der[12:]), "alg": "Ed25519", "use": "sig"}
        )
        self._kid = self._public.thumbprint()

    @property
    def kid(self) -> str:
        return self._kid

    @property
    def key_id(self) -> str:
        return self._key_id

    def public_jwk(self) -> dict[str, Any]:
        jwk = self._public.as_dict(private=False)
        jwk["kid"] = self._kid
        return jwk

    def sign(self, signing_input: bytes) -> bytes:
        try:
            out = self._client.sign(
                KeyId=self._key_id,
                Message=signing_input,
                MessageType="RAW",
                SigningAlgorithm="ED25519_SHA_512",
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as 503 by the API, never a bad receipt
            raise SignerError(f"KMS Sign failed: {exc.__class__.__name__}") from exc
        sig = bytes(out["Signature"])
        if len(sig) != 64:
            raise SignerError(f"KMS returned a {len(sig)}-byte signature, expected 64")
        return sig


def _b64url(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
