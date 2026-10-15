"""Adversarial tests for receipts and portable presentations."""

import time

import pytest
from joserfc import jwt
from joserfc.jwk import OctKey, OKPKey

from poac.credentials.issuer import ReceiptIssuer, holder_thumbprint
from poac.credentials.presentation import create_kb_jwt, verify_presentation
from poac.protocol.models import CapabilityTier, HolderJwk, IdentityTier


@pytest.fixture
def holder_key():
    return OKPKey.generate_key("Ed25519")


@pytest.fixture
def issuer():
    return ReceiptIssuer.generate(issuer_url="https://poac.test")


def _issue(issuer, holder_key, ttl=300, tier=CapabilityTier.C2):
    jwk_dict = holder_key.as_dict(private=False)
    holder_jwk = HolderJwk(kty="OKP", crv="Ed25519", x=jwk_dict["x"])
    return issuer.issue(
        session_id="sess-1",
        capability_tier=tier,
        identity_tier=IdentityTier.I1,
        families=["nlu", "logic"],
        latencies_ms=[1200, 900],
        rounds_total=2,
        receipt_ttl_s=ttl,
        holder_jwk=holder_jwk,
    )


def test_valid_presentation_round_trip(issuer, holder_key):
    receipt = _issue(issuer, holder_key)
    kb = create_kb_jwt(holder_key, receipt, audience="https://rp.example", nonce="n-1")
    res = verify_presentation(
        receipt, kb, "https://rp.example", "n-1", issuer.jwks()
    )
    assert res.valid, res.reason
    assert res.capability_tier is CapabilityTier.C2
    assert res.identity_tier is IdentityTier.I1
    assert res.holder_thumbprint == holder_key.thumbprint()


def test_tampered_receipt_rejected(issuer, holder_key):
    receipt = _issue(issuer, holder_key)
    header, payload, sig = receipt.split(".")
    forged = ".".join([header, payload[:-4] + ("AAAA" if payload[-4:] != "AAAA" else "BBBB"), sig])
    kb = create_kb_jwt(holder_key, forged, "aud", "n")
    res = verify_presentation(forged, kb, "aud", "n", issuer.jwks())
    assert not res.valid and "signature" in res.reason


def test_wrong_holder_key_rejected(issuer, holder_key):
    receipt = _issue(issuer, holder_key)
    thief_key = OKPKey.generate_key("Ed25519")
    kb = create_kb_jwt(thief_key, receipt, "aud", "n")
    res = verify_presentation(receipt, kb, "aud", "n", issuer.jwks())
    assert not res.valid and "cnf.jkt" in res.reason


def test_wrong_audience_rejected(issuer, holder_key):
    receipt = _issue(issuer, holder_key)
    kb = create_kb_jwt(holder_key, receipt, "https://other.example", "n")
    res = verify_presentation(receipt, kb, "https://rp.example", "n", issuer.jwks())
    assert not res.valid and "audience" in res.reason


def test_wrong_nonce_rejected(issuer, holder_key):
    receipt = _issue(issuer, holder_key)
    kb = create_kb_jwt(holder_key, receipt, "aud", "stale-nonce")
    res = verify_presentation(receipt, kb, "aud", "fresh-nonce", issuer.jwks())
    assert not res.valid and "nonce" in res.reason


def test_kb_bound_to_different_receipt_rejected(issuer, holder_key):
    receipt_a = _issue(issuer, holder_key)
    receipt_b = _issue(issuer, holder_key, tier=CapabilityTier.C3)
    kb_for_a = create_kb_jwt(holder_key, receipt_a, "aud", "n")
    res = verify_presentation(receipt_b, kb_for_a, "aud", "n", issuer.jwks())
    assert not res.valid and "different receipt" in res.reason


def test_expired_receipt_rejected(holder_key):
    past = int(time.time()) - 10_000
    issuer = ReceiptIssuer.generate()
    issuer._now = lambda: past  # issue in the past
    receipt = _issue(issuer, holder_key, ttl=300)
    kb = create_kb_jwt(holder_key, receipt, "aud", "n")
    res = verify_presentation(receipt, kb, "aud", "n", issuer.jwks())
    assert not res.valid and "expired" in res.reason


def test_stale_kb_jwt_rejected(issuer, holder_key):
    receipt = _issue(issuer, holder_key)
    old = int(time.time()) - 600
    kb = create_kb_jwt(holder_key, receipt, "aud", "n", now=old)
    res = verify_presentation(receipt, kb, "aud", "n", issuer.jwks())
    assert not res.valid and "iat" in res.reason


def test_unbound_i0_receipt_not_portable(issuer, holder_key):
    receipt = issuer.issue(
        session_id="s",
        capability_tier=CapabilityTier.C1,
        identity_tier=IdentityTier.I0,
        families=["nlu"],
        latencies_ms=[1000],
        rounds_total=1,
        receipt_ttl_s=300,
        holder_jwk=None,
    )
    kb = create_kb_jwt(holder_key, receipt, "aud", "n")
    res = verify_presentation(receipt, kb, "aud", "n", issuer.jwks())
    assert not res.valid and "cnf.jkt" in res.reason


def test_algorithm_confusion_rejected(issuer, holder_key):
    """Receipt re-signed with HS256 using a symmetric key must be rejected."""
    receipt = _issue(issuer, holder_key)
    from joserfc.jwk import KeySet

    claims = jwt.decode(
        receipt, KeySet.import_key_set(issuer.jwks()), registry=__import__(
            "poac.credentials.issuer", fromlist=["EDDSA_REGISTRY"]
        ).EDDSA_REGISTRY,
    ).claims
    oct_key = OctKey.import_key("attacker-known-secret-value-000000")
    forged = jwt.encode({"alg": "HS256", "typ": "poac+jwt"}, claims, oct_key)
    kb = create_kb_jwt(holder_key, forged, "aud", "n")
    res = verify_presentation(forged, kb, "aud", "n", issuer.jwks())
    assert not res.valid and "signature" in res.reason


def test_kb_with_private_key_in_header_rejected(issuer, holder_key):
    receipt = _issue(issuer, holder_key)
    kb = create_kb_jwt(holder_key, receipt, "aud", "n")
    # rebuild the KB with a header that leaks/carries private material
    import base64
    import json

    from poac.credentials.presentation import KB_TYP, receipt_hash

    header = {
        "alg": "Ed25519",
        "typ": KB_TYP,
        "jwk": holder_key.as_dict(private=True),
    }
    from poac.credentials.issuer import EDDSA_REGISTRY

    claims = {
        "aud": "aud",
        "nonce": "n",
        "iat": int(time.time()),
        "receipt_hash": receipt_hash(receipt),
    }
    evil_kb = jwt.encode(header, claims, holder_key, registry=EDDSA_REGISTRY)
    res = verify_presentation(receipt, evil_kb, "aud", "n", issuer.jwks())
    assert not res.valid and "public jwk" in res.reason


def test_key_rotation_old_key_still_in_jwks(holder_key):
    old_issuer = ReceiptIssuer.generate(issuer_url="https://poac.test")
    new_issuer = ReceiptIssuer.generate(issuer_url="https://poac.test")
    receipt = _issue(old_issuer, holder_key)
    kb = create_kb_jwt(holder_key, receipt, "aud", "n")

    # rotated JWKS still contains the old public key -> verification succeeds
    combined = {"keys": new_issuer.jwks()["keys"] + old_issuer.jwks()["keys"]}
    assert verify_presentation(receipt, kb, "aud", "n", combined).valid

    # old key removed -> verification fails
    only_new = new_issuer.jwks()
    res = verify_presentation(receipt, kb, "aud", "n", only_new)
    assert not res.valid


def test_holder_thumbprint_matches_joserfc(holder_key):
    jwk_dict = holder_key.as_dict(private=False)
    model = HolderJwk(kty="OKP", crv="Ed25519", x=jwk_dict["x"])
    assert holder_thumbprint(model) == holder_key.thumbprint()
