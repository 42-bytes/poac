"""End-to-end HTTP tests: sessions, verification, discovery, abuse guards."""

import pytest
from fastapi.testclient import TestClient
from joserfc.jwk import OKPKey

from poac.api.app import create_app
from poac.credentials.issuer import ReceiptIssuer
from poac.credentials.presentation import create_kb_jwt
from poac.protocol.models import CapabilityManifest
from poac.reference.solver import solve
from poac.challenges.registry import GENERATORS
from poac.protocol.models import (
    CodeChallenge,
    DataChallenge,
    DiagramChallenge,
    LogicChallenge,
    NluChallenge,
    ProofChallenge,
)

_PAYLOADS = {
    "nlu": NluChallenge,
    "code": CodeChallenge,
    "logic": LogicChallenge,
    "data": DataChallenge,
    "diagram": DiagramChallenge,
    "proof": ProofChallenge,
}


@pytest.fixture
def issuer():
    return ReceiptIssuer.generate(issuer_url="http://testserver")


@pytest.fixture
def client(issuer):
    return TestClient(create_app(issuer=issuer))


def _parse_challenge(round_data: dict):
    fam = round_data["challenge"]["family"]
    return _PAYLOADS[fam].model_validate(round_data["challenge"])


def _play_session(client, tier="C1", holder_jwk=None) -> dict:
    body = {"tier": tier}
    if holder_jwk:
        body["holder_jwk"] = holder_jwk
    resp = client.post("/v1/sessions", json=body)
    assert resp.status_code == 201, resp.text
    data = resp.json()
    rnd = data["round"]
    while True:
        answer = solve(_parse_challenge(rnd))
        resp = client.post(
            f"/v1/sessions/{data['session_id']}/rounds/{rnd['round_index']}",
            json={"nonce": rnd["nonce"], "answer": answer},
        )
        assert resp.status_code == 200, resp.text
        outcome = resp.json()
        if outcome["status"] == "next":
            rnd = outcome["round"]
            continue
        return outcome


def test_full_c1_flow_over_http(client):
    outcome = _play_session(client, "C1")
    assert outcome["status"] == "passed"
    assert outcome["identity_tier"] == "I0"
    assert len(outcome["latency_ms"]) == 3


def test_full_flow_with_holder_key_and_portable_verify(client):
    holder_key = OKPKey.generate_key("Ed25519")
    jwk = {k: v for k, v in holder_key.as_dict(private=False).items() if k in ("kty", "crv", "x")}
    outcome = _play_session(client, "C2", holder_jwk=jwk)
    assert outcome["status"] == "passed"
    assert outcome["identity_tier"] == "I1"

    receipt = outcome["receipt"]
    nonce = client.get("/v1/verify/nonce").json()["nonce"]
    kb = create_kb_jwt(holder_key, receipt, audience="https://rp.example", nonce=nonce)
    resp = client.post(
        "/v1/verify",
        json={
            "receipt": receipt,
            "kb_jwt": kb,
            "audience": "https://rp.example",
            "nonce": nonce,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is True
    assert body["capability_tier"] == "C2"

    # replaying the same verifier nonce is rejected
    resp2 = client.post(
        "/v1/verify",
        json={
            "receipt": receipt,
            "kb_jwt": kb,
            "audience": "https://rp.example",
            "nonce": nonce,
        },
    )
    assert resp2.json()["valid"] is False
    assert "nonce" in resp2.json()["reason"]


def test_unknown_fields_rejected_with_422(client):
    resp = client.post("/v1/sessions", json={"tier": "C1", "extra": True})
    assert resp.status_code == 422


def test_unknown_session_404(client):
    resp = client.post(
        "/v1/sessions/nope/rounds/1", json={"nonce": "n", "answer": "a"}
    )
    assert resp.status_code == 404


def test_wrong_answer_fails_session_over_http(client):
    resp = client.post("/v1/sessions", json={"tier": "C1"})
    data = resp.json()
    rnd = data["round"]
    resp = client.post(
        f"/v1/sessions/{data['session_id']}/rounds/{rnd['round_index']}",
        json={"nonce": rnd["nonce"], "answer": "wrong"},
    )
    assert resp.json()["status"] == "failed"
    assert resp.json()["failure"] == "wrong_answer"


def test_oversized_body_rejected(client):
    resp = client.post(
        "/v1/sessions",
        content=b"x" * 10,
        headers={"content-length": str(1024 * 1024), "content-type": "application/json"},
    )
    assert resp.status_code == 413


def test_session_rate_limit(client):
    codes = [
        client.post("/v1/sessions", json={"tier": "C0"}).status_code
        for _ in range(31)
    ]
    assert codes.count(201) == 30
    assert codes[-1] == 429


def test_discovery_surfaces(client):
    # human notice states purpose + limitations
    home = client.get("/")
    assert home.status_code == 200
    assert "reverse CAPTCHA" in home.text
    assert "does NOT prove" in home.text.replace("does <strong>NOT</strong> prove", "does NOT prove") or "NOT prove" in home.text

    # llms.txt is served and mentions the endpoints
    llms = client.get("/llms.txt")
    assert llms.status_code == 200
    assert "/v1/sessions" in llms.text

    # machine-readable manifest validates against the published model
    manifest = client.get("/.well-known/agent-capability.json")
    assert manifest.status_code == 200
    parsed = CapabilityManifest.model_validate(manifest.json())
    tier_names = {t.tier.value for t in parsed.tiers}
    # C0-C3 always; C4 only when the host has a Lean toolchain
    assert {"C0", "C1", "C2", "C3"} <= tier_names <= {"C0", "C1", "C2", "C3", "C4"}
    assert "NOT prove" in parsed.honest_claims

    # issuer keys published
    jwks = client.get("/.well-known/jwks.json")
    assert jwks.status_code == 200
    assert jwks.json()["keys"][0]["kty"] == "OKP"

    # Link headers advertised on every response
    assert 'rel="describedby"' in home.headers["link"]
    assert "/openapi.json" in home.headers["link"]


def test_openapi_documents_endpoints(client):
    spec = client.get("/openapi.json").json()
    assert "/v1/sessions" in spec["paths"]
    assert "/v1/sessions/{session_id}/rounds/{round_index}" in spec["paths"]
    assert "/v1/verify" in spec["paths"]
    assert "/v1/verify/nonce" in spec["paths"]
    schemas = spec["components"]["schemas"]
    for name in ("NluChallenge", "CodeChallenge", "LogicChallenge", "DataChallenge", "DiagramChallenge"):
        assert name in schemas


def test_all_short_answer_families_solvable_over_http(issuer):
    """Play many C2/C3 sessions so every short-answer family appears."""
    client = TestClient(create_app(issuer=issuer))
    seen: set[str] = set()
    for i in range(6):
        outcome = _play_session(client, "C3" if i % 2 else "C2")
        assert outcome["status"] == "passed"
        seen.update(outcome["families"])
    assert seen == set(GENERATORS) - {"proof"}
