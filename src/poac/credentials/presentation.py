"""Portable presentation: holder-signed Key-Binding JWT over aud+nonce+hash.

Pattern follows RFC 9901 key binding and RFC 9449 (DPoP) proof-of-possession:
the KB-JWT carries the holder's public JWK in its header; the verifier checks
that this key's RFC 7638 thumbprint equals the receipt's ``cnf.jkt`` claim,
so a stolen receipt is useless without the holder's private key.

Only EdDSA is accepted for both signatures; ``typ`` values are pinned.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Callable

from cryptography.exceptions import InvalidSignature
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet, OKPKey
from joserfc.jws import JWSRegistry

from poac.credentials.issuer import ALLOWED_ALG, EDDSA_REGISTRY, RECEIPT_TYP
from poac.credentials.signer import ALG_ED25519, ALG_MLDSA65, mldsa65_public_key
from poac.protocol.models import (
    CapabilityTier,
    IdentityTier,
    PresentationResult,
)

KB_TYP = "poac-kb+jwt"
MAX_KB_AGE_S = 120
_REGISTRY = EDDSA_REGISTRY  # reject any alg other than EdDSA


def receipt_hash(receipt: str) -> str:
    return base64.urlsafe_b64encode(
        hashlib.sha256(receipt.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")


def create_kb_jwt(
    holder_key: OKPKey,
    receipt: str,
    audience: str,
    nonce: str,
    now: int | None = None,
) -> str:
    """Holder-side helper (used by tests, benchmarks, and client examples)."""
    header = {
        "alg": ALLOWED_ALG,
        "typ": KB_TYP,
        "jwk": holder_key.as_dict(private=False),
    }
    claims = {
        "aud": audience,
        "nonce": nonce,
        "iat": now if now is not None else int(time.time()),
        "receipt_hash": receipt_hash(receipt),
    }
    return jwt.encode(header, claims, holder_key, registry=_REGISTRY)


def _reject(reason: str) -> PresentationResult:
    return PresentationResult(valid=False, reason=reason)


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _decode_receipt(receipt: str, issuer_jwks: dict) -> tuple[dict, list[str]] | str:
    """Verify every signature on a receipt (compact or JSON general
    serialisation) against the issuer JWKS. Returns ``(claims, algs)`` or a
    rejection reason. Policy: Ed25519 is always required; an ML-DSA-65
    signature, when present, must also verify; nothing else is accepted."""
    if not receipt.startswith("{"):
        try:
            keyset = KeySet.import_key_set(issuer_jwks)
            decoded = jwt.decode(receipt, keyset, registry=_REGISTRY)
        except (JoseError, ValueError) as exc:
            return f"receipt signature invalid: {exc.__class__.__name__}"
        if decoded.header.get("typ") != RECEIPT_TYP:
            return "receipt typ mismatch"
        return decoded.claims, [ALG_ED25519]

    try:
        obj = json.loads(receipt)
        payload: str = obj["payload"]
        sigs: list = obj["signatures"]
        if not isinstance(payload, str) or not isinstance(sigs, list) or not 1 <= len(sigs) <= 2:
            raise ValueError
        claims = json.loads(_b64d(payload))
        if not isinstance(claims, dict):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        return "receipt json serialisation malformed"
    keys_by_kid = {k.get("kid"): k for k in issuer_jwks.get("keys", [])}
    algs: list[str] = []
    for sig in sigs:
        try:
            protected, signature = sig["protected"], sig["signature"]
            header = json.loads(_b64d(protected))
            raw_sig = _b64d(signature)
        except (KeyError, TypeError, ValueError):
            return "receipt signature entry malformed"
        if header.get("typ") != RECEIPT_TYP:
            return "receipt typ mismatch"
        if "crit" in header or sig.get("header"):
            return "receipt header has unsupported members"
        alg, jwk = header.get("alg"), keys_by_kid.get(header.get("kid"))
        if alg in algs:
            return "receipt has duplicate signature algorithms"
        if jwk is None:
            return "receipt signature invalid: unknown kid"
        signing_input = f"{protected}.{payload}".encode("ascii")
        try:
            if alg == ALG_ED25519 and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
                OKPKey.import_key(jwk).public_key.verify(raw_sig, signing_input)
            elif alg == ALG_MLDSA65 and jwk.get("kty") == "AKP":
                mldsa65_public_key(jwk).verify(raw_sig, signing_input)
            else:
                return f"receipt signature invalid: alg {alg!r} not accepted"
        except (InvalidSignature, ValueError, JoseError):
            return f"receipt signature invalid: {alg}"
        algs.append(alg)
    if ALG_ED25519 not in algs:
        return "receipt lacks the Ed25519 signature"
    return claims, algs


def verify_presentation(
    receipt: str,
    kb_jwt: str,
    audience: str,
    nonce: str,
    issuer_jwks: dict,
    now: Callable[[], int] | None = None,
    expected_issuer: str | None = None,
    require_pq: bool = False,
) -> PresentationResult:
    """Full verification chain; any failure is a hard reject with a reason.

    ``expected_issuer`` pins the receipt's ``iss`` claim (exact string match):
    a verifier passes its own issuer URL so a receipt from any other issuer
    — even one whose key somehow made it into the JWKS — is refused.
    ``require_pq`` additionally demands a valid ML-DSA-65 signature (only
    ``json-dual`` receipts carry one)."""
    now_fn = now or (lambda: int(time.time()))

    # 1. issuer signature(s) and pinned typ
    decoded = _decode_receipt(receipt, issuer_jwks)
    if isinstance(decoded, str):
        return _reject(decoded)
    claims, algs = decoded
    if require_pq and ALG_MLDSA65 not in algs:
        return _reject("receipt lacks the required ML-DSA-65 signature")
    if expected_issuer is not None and claims.get("iss") != expected_issuer:
        return _reject("receipt issuer mismatch")

    # 2. receipt freshness
    exp, iat = claims.get("exp"), claims.get("iat")
    if not isinstance(exp, int) or not isinstance(iat, int):
        return _reject("receipt missing iat/exp")
    if now_fn() >= exp:
        return _reject("receipt expired")

    # 3. holder binding required for portability
    jkt = (claims.get("cnf") or {}).get("jkt")
    if not jkt:
        return _reject("receipt has no cnf.jkt holder binding (I0 receipts are not portable)")

    # 4. KB-JWT: header carries the holder public key; verify signature with it
    try:
        header_seg = kb_jwt.split(".")[0]
        padded = header_seg + "=" * (-len(header_seg) % 4)
        import json

        kb_header = json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return _reject("kb-jwt malformed")
    if kb_header.get("typ") != KB_TYP or kb_header.get("alg") != ALLOWED_ALG:
        return _reject("kb-jwt typ/alg mismatch")
    jwk = kb_header.get("jwk")
    if not isinstance(jwk, dict) or "d" in jwk:
        return _reject("kb-jwt header must carry a public jwk")
    try:
        holder_key = OKPKey.import_key(jwk)
        kb = jwt.decode(kb_jwt, holder_key, registry=_REGISTRY)
    except (JoseError, ValueError) as exc:
        return _reject(f"kb-jwt signature invalid: {exc.__class__.__name__}")

    # 5. thumbprint of the KB signing key must equal the receipt's cnf.jkt
    if holder_key.thumbprint() != jkt:
        return _reject("holder key does not match receipt cnf.jkt")

    # 6. audience, nonce, receipt hash, freshness of the KB proof
    if kb.claims.get("aud") != audience:
        return _reject("kb-jwt audience mismatch")
    if kb.claims.get("nonce") != nonce:
        return _reject("kb-jwt nonce mismatch")
    if kb.claims.get("receipt_hash") != receipt_hash(receipt):
        return _reject("kb-jwt bound to a different receipt")
    kb_iat = kb.claims.get("iat")
    if not isinstance(kb_iat, int) or abs(now_fn() - kb_iat) > MAX_KB_AGE_S:
        return _reject("kb-jwt iat outside allowed window")

    poac = claims.get("poac") or {}
    return PresentationResult(
        valid=True,
        capability_tier=CapabilityTier(poac.get("capability_tier")),
        identity_tier=IdentityTier(poac.get("identity_tier")),
        holder_thumbprint=jkt,
        issued_at=iat,
        expires_at=exp,
        signature_algs=algs,
    )
