"""Key rotation (hardening H1): previous public keys stay in the JWKS until
their `retire_at`, the `poac-keys` CLI manages the previous-keys file for
local and KMS-backed issuers, and in-flight receipts survive a rotation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from joserfc.jwk import OKPKey

from poac.credentials import keys_cli
from poac.credentials.issuer import ReceiptIssuer
from poac.credentials.keyring import load_previous_keys, save_previous_keys
from poac.credentials.presentation import create_kb_jwt, verify_presentation
from poac.credentials.signer import KmsSigner
from poac.protocol.models import CapabilityTier, HolderJwk, IdentityTier
from tests.test_signer import FakeKms

AUD = "https://rp.example"
T0 = 1_800_000_000


def _issue(issuer, holder):
    x = holder.as_dict(private=False)["x"]
    return issuer.issue(session_id="s", capability_tier=CapabilityTier.C1, identity_tier=IdentityTier.I1,
                        families=["nlu"], latencies_ms=[1], rounds_total=1, receipt_ttl_s=300,
                        holder_jwk=HolderJwk(kty="OKP", crv="Ed25519", x=x))


def _ok(receipt, holder, jwks, now):
    kb = create_kb_jwt(holder, receipt, audience=AUD, nonce="n", now=now)
    return verify_presentation(receipt, kb, AUD, "n", jwks, now=lambda: now)


def test_previous_key_published_until_retire_at_then_dropped():
    holder = OKPKey.generate_key("Ed25519")
    old = ReceiptIssuer(OKPKey.generate_key("Ed25519"), "https://poac.test", now=lambda: T0)
    old_receipt = _issue(old, holder)
    prev = dict(old.jwks()["keys"][0], retire_at=T0 + 100)

    clock = {"t": T0}
    new = ReceiptIssuer(OKPKey.generate_key("Ed25519"), "https://poac.test",
                        now=lambda: clock["t"], previous_keys=[prev], pq_signer=None)
    kids = [k["kid"] for k in new.jwks()["keys"]]
    assert kids == [new.signer.kid, old.signer.kid] and len(set(kids)) == 2
    assert all("retire_at" not in k and "d" not in k for k in new.jwks()["keys"])
    assert _ok(old_receipt, holder, new.jwks(), T0 + 50).valid
    assert _ok(_issue(new, holder), holder, new.jwks(), T0 + 50).valid

    clock["t"] = T0 + 100  # retire_at reached
    assert [k["kid"] for k in new.jwks()["keys"]] == [new.signer.kid]
    res = _ok(old_receipt, holder, new.jwks(), T0 + 100)
    assert not res.valid and "signature invalid" in res.reason


def test_previous_keys_file_round_trip_and_akp(tmp_path):
    p = tmp_path / "previous-keys.json"
    assert load_previous_keys(p) == []  # missing file is fine
    ed = ReceiptIssuer.generate("x").jwks()["keys"]
    save_previous_keys(p, [dict(ed[0], retire_at=T0), dict(ed[1], retire_at=T0 + 5)])
    loaded = load_previous_keys(p)
    assert [k["kty"] for k in loaded] == ["OKP", "AKP"] and all(k["retire_at"] for k in loaded)
    # a private part never gets written
    priv = OKPKey.generate_key("Ed25519").as_dict(private=True)
    with pytest.raises(ValueError):
        save_previous_keys(p, [dict(priv, retire_at=T0)])
    # ML-DSA previous key is published by the issuer too
    issuer = ReceiptIssuer(OKPKey.generate_key("Ed25519"), now=lambda: T0 + 1, previous_keys=loaded)
    assert [k["kty"] for k in issuer.jwks()["keys"]] == ["OKP", "AKP"]  # OKP retired at T0, AKP still live


def test_rotate_local_cli_round_trip(tmp_path, capsys):
    keyfile, prev = tmp_path / "issuer.jwk", tmp_path / "previous-keys.json"
    holder = OKPKey.generate_key("Ed25519")
    first = OKPKey.generate_key("Ed25519", {"alg": "Ed25519", "use": "sig"})
    keyfile.write_text(json.dumps(first.as_dict(private=True)))
    receipt_before = _issue(ReceiptIssuer(first, "https://poac.test", now=lambda: T0), holder)

    rc = keys_cli.main(["rotate-local", "--issuer-key-file", str(keyfile),
                        "--previous-keys-file", str(prev), "--retire-after", "24h",
                        "--now", str(T0)])
    assert rc == 0
    out = capsys.readouterr().err
    assert first.thumbprint() in out and "retire_at" in out

    new_key = OKPKey.import_key(json.loads(keyfile.read_text()))
    assert new_key.is_private and new_key.thumbprint() != first.thumbprint()
    assert oct(keyfile.stat().st_mode)[-3:] == "600"
    previous = load_previous_keys(prev)
    assert [k["kid"] for k in previous] == [first.thumbprint()]
    assert previous[0]["retire_at"] == T0 + 86_400 and "d" not in previous[0]

    issuer = ReceiptIssuer(new_key, "https://poac.test", now=lambda: T0 + 10, previous_keys=previous)
    assert _ok(receipt_before, holder, issuer.jwks(), T0 + 10).valid
    assert _ok(_issue(issuer, holder), holder, issuer.jwks(), T0 + 10).valid

    # a second rotation keeps both older keys until each retires, pruning expired ones
    rc = keys_cli.main(["rotate-local", "--issuer-key-file", str(keyfile),
                        "--previous-keys-file", str(prev), "--retire-after", "1h",
                        "--now", str(T0 + 90_000)])
    assert rc == 0
    kids = [k["kid"] for k in load_previous_keys(prev)]
    assert kids == [new_key.thumbprint()]  # first key (retire T0+86400) pruned at T0+90000


def test_retire_kms_cli_snapshots_public_key(tmp_path, capsys):
    fake = FakeKms()
    prev = tmp_path / "previous-keys.json"
    rc = keys_cli.main(["retire-kms", "--key", "arn:fake:old", "--previous-keys-file", str(prev),
                        "--retire-after", "2h", "--now", str(T0)], kms_client=fake)
    assert rc == 0
    entry = load_previous_keys(prev)[0]
    assert entry["kid"] == KmsSigner("arn:fake:old", client=fake).kid
    assert entry["retire_at"] == T0 + 7200 and entry["kty"] == "OKP"
    # idempotent: retiring the same key again replaces, not duplicates
    keys_cli.main(["retire-kms", "--key", "arn:fake:old", "--previous-keys-file", str(prev),
                   "--retire-after", "3h", "--now", str(T0)], kms_client=fake)
    loaded = load_previous_keys(prev)
    assert len(loaded) == 1 and loaded[0]["retire_at"] == T0 + 10_800

    rc = keys_cli.main(["show", "--previous-keys-file", str(prev), "--now", str(T0)])
    assert rc == 0 and entry["kid"] in capsys.readouterr().out


def test_retire_after_parsing():
    assert keys_cli.parse_duration("24h") == 86_400
    assert keys_cli.parse_duration("90m") == 5_400
    assert keys_cli.parse_duration("45s") == 45
    assert keys_cli.parse_duration("2d") == 172_800
    with pytest.raises(ValueError):
        keys_cli.parse_duration("soon")
