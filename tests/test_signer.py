"""Signer seam (hardening H5b): receipts can be signed by a local key or by
AWS KMS; relying parties verify against the published JWKS either way."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from joserfc.jwk import OKPKey

from poac.credentials.issuer import ReceiptIssuer
from poac.credentials.presentation import create_kb_jwt, verify_presentation
from poac.credentials.signer import KmsSigner, LocalKeySigner, SignerError
from poac.protocol.models import CapabilityTier, HolderJwk, IdentityTier


class FakeKms:
    """Just enough of boto3's KMS client: the private key never leaves here."""

    def __init__(self, fail: bool = False):
        self._priv = Ed25519PrivateKey.generate()
        self.fail = fail
        self.calls: list[dict] = []

    def get_public_key(self, KeyId):
        der = self._priv.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return {"KeyId": KeyId, "KeySpec": "ECC_NIST_EDWARDS25519", "PublicKey": der,
                "SigningAlgorithms": ["ED25519_SHA_512", "ED25519_PH_SHA_512"]}

    def sign(self, **kw):
        self.calls.append(kw)
        if self.fail:
            raise RuntimeError("KMSInternalException: boom")
        assert kw["MessageType"] == "RAW" and kw["SigningAlgorithm"] == "ED25519_SHA_512"
        return {"Signature": self._priv.sign(kw["Message"]), "SigningAlgorithm": "ED25519_SHA_512"}


def _holder():
    k = OKPKey.generate_key("Ed25519")
    d = k.as_dict(private=False)
    return k, HolderJwk(kty="OKP", crv="Ed25519", x=d["x"])


def _issue(issuer, holder_jwk=None):
    return issuer.issue(session_id="s1", capability_tier=CapabilityTier.C1,
                        identity_tier=IdentityTier.I1 if holder_jwk else IdentityTier.I0,
                        families=["nlu"], latencies_ms=[100], rounds_total=1,
                        receipt_ttl_s=300, holder_jwk=holder_jwk)


def _present_ok(issuer, receipt, holder_key):
    kb = create_kb_jwt(holder_key, receipt, "https://rp.example", "n1")
    res = verify_presentation(receipt, kb, audience="https://rp.example", nonce="n1",
                              issuer_jwks=issuer.jwks())
    return res.valid, res.reason


def test_local_signer_matches_legacy_constructor():
    key = OKPKey.generate_key("Ed25519")
    legacy = ReceiptIssuer(key, issuer_url="https://poac.test")
    seam = ReceiptIssuer(LocalKeySigner(key), issuer_url="https://poac.test")
    assert legacy.jwks() == seam.jwks()
    hk, hj = _holder()
    assert _present_ok(legacy, _issue(seam, hj), hk) == (True, None)


def test_kms_signer_issues_verifiable_receipts():
    kms = FakeKms()
    signer = KmsSigner("arn:aws:kms:eu-north-1:1:key/abc", client=kms)
    issuer = ReceiptIssuer(signer, issuer_url="https://poac.test")
    hk, hj = _holder()
    receipt = _issue(issuer, hj)
    assert _present_ok(issuer, receipt, hk) == (True, None)
    # header carries the KMS key's thumbprint and the pinned alg
    header = receipt.split(".")[0]
    header_json = base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)).decode()
    assert '"alg":"Ed25519"' in header_json.replace(" ", "")
    assert signer.kid in header_json
    assert kms.calls and kms.calls[0]["KeyId"] == "arn:aws:kms:eu-north-1:1:key/abc"
    # JWKS exposes only public material
    jwk = issuer.jwks()["keys"][0]
    assert jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519" and "d" not in jwk
    assert jwk["kid"] == signer.kid


def test_kms_failure_is_a_signer_error_not_a_receipt():
    issuer = ReceiptIssuer(KmsSigner("arn:x", client=FakeKms(fail=True)), issuer_url="u")
    with pytest.raises(SignerError):
        _issue(issuer)


def test_previous_keys_stay_in_jwks_for_the_switchover():
    old = OKPKey.generate_key("Ed25519")
    old_issuer = ReceiptIssuer(old, issuer_url="https://poac.test")
    hk, hj = _holder()
    old_receipt = _issue(old_issuer, hj)

    new_issuer = ReceiptIssuer(KmsSigner("arn:x", client=FakeKms()), issuer_url="https://poac.test",
                               previous_keys=[old.as_dict(private=False)])
    kids = [k["kid"] for k in new_issuer.jwks()["keys"]]
    assert len(kids) == 2 and kids[0] == new_issuer.signer.kid  # current first
    assert _present_ok(new_issuer, old_receipt, hk) == (True, None)   # in-flight receipts survive
    assert _present_ok(new_issuer, _issue(new_issuer, hj), hk) == (True, None)
    # a private JWK offered as a previous key is a configuration error, not something to strip quietly
    with pytest.raises(ValueError):
        ReceiptIssuer(KmsSigner("arn:x", client=FakeKms()), issuer_url="u",
                      previous_keys=[old.as_dict(private=True)])
    assert all("d" not in k for k in new_issuer.jwks()["keys"])


def test_signer_outage_is_503_for_a_passed_session():
    from fastapi.testclient import TestClient

    from poac.api.app import create_app
    from poac.client import PoacClient, PoacError
    from poac.reference.solver import solve
    from poac.sessions.orchestrator import Orchestrator

    kms = FakeKms()
    issuer = ReceiptIssuer(KmsSigner("arn:x", client=kms), issuer_url="http://testserver")
    app = create_app(issuer=issuer, orchestrator=Orchestrator(issuer, lean_bin=None),
                     lean_bin=None, session_rate_per_minute=10_000)
    client = PoacClient("http://testserver", http=TestClient(app))
    kms.fail = True
    with pytest.raises(PoacError) as exc:
        client.earn("C0", solver=solve)
    assert "503" in str(exc.value) and "signing unavailable" in str(exc.value)
    kms.fail = False
    assert client.earn("C0", solver=solve).tier == "C0"  # recovers without restart


def test_kms_signer_rejects_non_ed25519_keys():
    class WrongKms(FakeKms):
        def get_public_key(self, KeyId):
            return {**super().get_public_key(KeyId), "KeySpec": "ECC_NIST_P256"}

    with pytest.raises(SignerError):
        KmsSigner("arn:x", client=WrongKms())
