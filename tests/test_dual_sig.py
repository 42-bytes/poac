"""Dual-signed receipts (hardening H5d): JWS JSON serialisation carrying an
Ed25519 and an ML-DSA-65 (RFC 9964, post-quantum) signature over the same
payload. Compact Ed25519 stays the default; `json-dual` is opt-in per
session; relying parties may demand the PQ signature with `require_pq`."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from joserfc.jwk import OKPKey

from poac.api.app import create_app
from poac.client import PoacClient, PoacError, receipt_issuer
from poac.credentials.issuer import ReceiptIssuer
from poac.credentials.presentation import create_kb_jwt, verify_presentation
from poac.credentials.signer import KmsMlDsaSigner, LocalMlDsaSigner, SignerError, akp_jwk
from poac.protocol.models import CapabilityTier, HolderJwk, IdentityTier
from poac.reference.solver import solve
from poac.rp import PoacGate

AUD = "https://rp.example"


class FakeKmsMlDsa:
    def __init__(self):
        self._priv = mldsa.MLDSA65PrivateKey.generate()
        self.calls = 0

    def get_public_key(self, KeyId):
        der = self._priv.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return {"KeyId": KeyId, "KeySpec": "ML_DSA_65", "PublicKey": der}

    def sign(self, **kw):
        self.calls += 1
        assert kw["MessageType"] == "RAW" and kw["SigningAlgorithm"] == "ML_DSA_SHAKE_256"
        return {"Signature": self._priv.sign(kw["Message"])}


@pytest.fixture
def holder():
    return OKPKey.generate_key("Ed25519")


def _issue(issuer, holder, fmt, session_id="s"):
    x = holder.as_dict(private=False)["x"]
    return issuer.issue(session_id=session_id, capability_tier=CapabilityTier.C2, identity_tier=IdentityTier.I1,
                        families=["nlu"], latencies_ms=[1000], rounds_total=1, receipt_ttl_s=300,
                        holder_jwk=HolderJwk(kty="OKP", crv="Ed25519", x=x), receipt_format=fmt)


def _verify(issuer, holder, receipt, **kw):
    kb = create_kb_jwt(holder, receipt, audience=AUD, nonce="n")
    return verify_presentation(receipt, kb, AUD, "n", issuer.jwks(), **kw)


# --- key material -------------------------------------------------------------------


def test_akp_jwk_shape_and_thumbprint():
    jwk = LocalMlDsaSigner.generate().public_jwk()
    assert jwk["kty"] == "AKP" and jwk["alg"] == "ML-DSA-65" and "priv" not in jwk
    assert len(jwk["pub"]) == 2603  # 1952 bytes base64url, no padding
    # RFC 7638 thumbprint over the required members in lexicographic order
    import base64, hashlib
    canon = json.dumps({"alg": "ML-DSA-65", "kty": "AKP", "pub": jwk["pub"]}, separators=(",", ":"))
    assert jwk["kid"] == base64.urlsafe_b64encode(hashlib.sha256(canon.encode()).digest()).rstrip(b"=").decode()
    with pytest.raises(SignerError):
        akp_jwk(b"short")


def test_kms_mldsa_signer_matches_local_shape():
    fake = FakeKmsMlDsa()
    kms = KmsMlDsaSigner("arn:fake", client=fake)
    assert kms.alg == "ML-DSA-65" and kms.public_jwk()["kty"] == "AKP"
    sig = kms.sign(b"x")
    assert len(sig) == 3309 and fake.calls == 1


def test_issuer_rejects_wrong_pq_alg():
    with pytest.raises(ValueError):
        ReceiptIssuer(OKPKey.generate_key("Ed25519"), pq_signer=ReceiptIssuer.generate().signer)


# --- issuance + verification ---------------------------------------------------------


def test_jwks_publishes_both_keys_and_formats():
    issuer = ReceiptIssuer.generate("https://poac.test")
    kinds = [(k["kty"], k["alg"]) for k in issuer.jwks()["keys"]]
    assert kinds == [("OKP", "Ed25519"), ("AKP", "ML-DSA-65")]
    assert issuer.receipt_formats == ["compact", "json-dual"]
    assert ReceiptIssuer.generate(pq=False).receipt_formats == ["compact"]


def test_dual_receipt_verifies_and_reports_algs(holder):
    issuer = ReceiptIssuer.generate("https://poac.test")
    receipt = _issue(issuer, holder, "json-dual")
    obj = json.loads(receipt)
    assert set(obj) == {"payload", "signatures"} and len(obj["signatures"]) == 2
    res = _verify(issuer, holder, receipt, expected_issuer="https://poac.test", require_pq=True)
    assert res.valid, res.reason
    assert res.signature_algs == ["Ed25519", "ML-DSA-65"]
    assert res.capability_tier is CapabilityTier.C2 and res.holder_thumbprint == holder.thumbprint()
    # compact stays compact and reports only Ed25519
    compact = _issue(issuer, holder, "compact")
    assert compact.count(".") == 2
    assert _verify(issuer, holder, compact).signature_algs == ["Ed25519"]


def test_require_pq_rejects_compact(holder):
    issuer = ReceiptIssuer.generate("https://poac.test")
    res = _verify(issuer, holder, _issue(issuer, holder, "compact"), require_pq=True)
    assert not res.valid and "ML-DSA-65" in res.reason


def test_every_present_signature_must_verify(holder):
    issuer = ReceiptIssuer.generate("https://poac.test")
    obj = json.loads(_issue(issuer, holder, "json-dual"))

    def tampered(i, field="signature"):
        o = json.loads(json.dumps(obj))
        s = o["signatures"][i][field]
        o["signatures"][i][field] = s[:-2] + ("AA" if s[-2:] != "AA" else "BB")
        return json.dumps(o, separators=(",", ":"))

    assert "ML-DSA-65" in _verify(issuer, holder, tampered(1)).reason
    assert "Ed25519" in _verify(issuer, holder, tampered(0)).reason
    # dropping the Ed25519 signature is not a PQ-only receipt, it is invalid
    pq_only = {"payload": obj["payload"], "signatures": [obj["signatures"][1]]}
    res = _verify(issuer, holder, json.dumps(pq_only, separators=(",", ":")))
    assert not res.valid and "Ed25519" in res.reason
    # the two signatures must be over the same payload
    other = json.loads(_issue(issuer, holder, "json-dual", session_id="s2"))
    mixed = {"payload": obj["payload"], "signatures": [obj["signatures"][0], other["signatures"][1]]}
    assert not _verify(issuer, holder, json.dumps(mixed)).valid


def test_pq_key_from_another_issuer_is_unknown_kid(holder):
    a = ReceiptIssuer.generate("https://poac.test")
    b = ReceiptIssuer.generate("https://poac.test")
    receipt = _issue(a, holder, "json-dual")
    kb = create_kb_jwt(holder, receipt, audience=AUD, nonce="n")
    jwks = {"keys": [a.jwks()["keys"][0], b.jwks()["keys"][1]]}  # right Ed25519, wrong ML-DSA key
    res = verify_presentation(receipt, kb, AUD, "n", jwks)
    assert not res.valid and "unknown kid" in res.reason


def test_dual_without_pq_signer_is_a_value_error(holder):
    issuer = ReceiptIssuer.generate(pq=False)
    with pytest.raises(ValueError):
        _issue(issuer, holder, "json-dual")


# --- end to end over HTTP --------------------------------------------------------------


@pytest.fixture
def http():
    return TestClient(create_app(lean_bin=None, session_rate_per_minute=10_000, base_url="http://poac.test"))


def test_agent_earns_dual_receipt_and_gate_can_require_pq(http):
    assert http.get("/.well-known/agent-capability.json").json()["receipt_formats"] == ["compact", "json-dual"]
    agent = PoacClient("http://poac.test", http=http)
    receipt = agent.earn("C1", solver=solve, receipt_format="json-dual")
    assert receipt.token.startswith("{") and receipt.claims["iss"] == "http://poac.test"
    iss, kids = receipt_issuer(receipt.token)
    assert iss == "http://poac.test" and len(kids) == 2

    rp = PoacClient("http://poac.test", http=http)
    nonce = rp.verify_nonce()
    kb = agent.present(receipt, audience=AUD, nonce=nonce)
    res = rp.verify(receipt, kb, audience=AUD, nonce=nonce, require_pq=True)
    assert res["valid"] and res["signature_algs"] == ["Ed25519", "ML-DSA-65"]

    # a gate that insists on PQ: dual receipt in the Authorization header passes,
    # a compact one is refused
    gate = PoacGate(verifier_url="http://poac.test", audience=AUD, http=http, require_pq=True)
    app = FastAPI()
    app.include_router(gate.router)

    @app.post("/posts")
    def post(agent=Depends(gate.require)):
        return {"tier": agent.tier}

    forum = TestClient(app)
    n = forum.get("/poac/nonce").json()["nonce"]
    kb = agent.present(receipt, audience=AUD, nonce=n)
    assert forum.post("/posts", headers={"Authorization": f"PoAC {receipt.token}", "PoAC-KB": kb}).status_code == 200

    compact = agent.earn("C1", solver=solve)
    n = forum.get("/poac/nonce").json()["nonce"]
    kb = agent.present(compact, audience=AUD, nonce=n)
    r = forum.post("/posts", headers={"Authorization": f"PoAC {compact.token}", "PoAC-KB": kb})
    assert r.status_code == 401 and "ML-DSA-65" in r.json()["detail"]


def test_verifier_without_pq_refuses_dual_requests_with_400():
    issuer = ReceiptIssuer.generate("http://poac.test", pq=False)
    http = TestClient(create_app(lean_bin=None, issuer=issuer, session_rate_per_minute=10_000,
                                 base_url="http://poac.test"))
    assert http.get("/.well-known/agent-capability.json").json()["receipt_formats"] == ["compact"]
    with pytest.raises(PoacError) as ei:
        PoacClient("http://poac.test", http=http).earn("C1", solver=solve, receipt_format="json-dual")
    assert "400" in str(ei.value) and "json-dual" in str(ei.value)
