"""The previous-keys file: public JWKs an issuer keeps publishing after a
rotation so receipts signed before the switch verify until they expire.

Format (``previous-keys.json``)::

    {"keys": [ {<public JWK with kid>, "retire_at": <unix seconds>}, ... ]}

``retire_at`` is a PoAC-private member; ``ReceiptIssuer.jwks()`` strips it
before publishing and drops the key once it is reached. Receipts live 300 s,
so a day is a generous window that also covers relying parties with a
cached JWKS.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from joserfc.jwk import OKPKey

from poac.credentials.signer import akp_jwk, mldsa65_public_key


def public_jwk_with_kid(jwk: dict[str, Any]) -> dict[str, Any]:
    """Validate a JWK as a *public* Ed25519 or ML-DSA-65 key and return a
    copy carrying its RFC 7638 ``kid`` (and any ``retire_at``)."""
    kty = jwk.get("kty")
    if kty == "OKP":
        if "d" in jwk:
            raise ValueError("previous key must be public (has 'd')")
        key = OKPKey.import_key({k: v for k, v in jwk.items() if k != "retire_at"})
        if key.curve_name != "Ed25519":
            raise ValueError("previous OKP key must be Ed25519")
        out = key.as_dict(private=False)
        out["kid"] = key.thumbprint()
    elif kty == "AKP":
        pub = mldsa65_public_key(jwk)  # raises on priv / wrong alg
        out = akp_jwk(pub.public_bytes_raw())
    else:
        raise ValueError(f"unsupported previous key type {kty!r}")
    if "retire_at" in jwk:
        out["retire_at"] = int(jwk["retire_at"])
    return out


def load_previous_keys(path: Path | str) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    data = json.loads(p.read_text())
    return [public_jwk_with_kid(k) for k in data.get("keys", [])]


def save_previous_keys(path: Path | str, keys: list[dict[str, Any]]) -> None:
    cleaned = [public_jwk_with_kid(k) for k in keys]
    for k in cleaned:
        if "retire_at" not in k:
            raise ValueError(f"previous key {k['kid']} needs a retire_at")
    p = Path(path)
    p.write_text(json.dumps({"keys": cleaned}, indent=1) + "\n")
