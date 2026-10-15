"""poac.rp — relying-party gate (phase 2, D3): a 15-line app gated end to end."""

from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from poac.api.app import create_app
from poac.client import PoacClient
from poac.reference.solver import solve
from poac.rp import PoacGate

AUD = "https://forum.example"


@pytest.fixture
def verifier():
    return TestClient(create_app(lean_bin=None, session_rate_per_minute=10_000, base_url="http://poac.test"))


@pytest.fixture
def forum(verifier):
    gate = PoacGate(verifier_url="http://poac.test", audience=AUD, min_tier="C1", http=verifier)
    app = FastAPI()
    app.include_router(gate.router)

    @app.post("/posts")
    def create_post(agent=Depends(gate.require)):
        return {"ok": True, "by": agent.holder_thumbprint, "tier": agent.tier}

    return TestClient(app)


def _earn_and_headers(verifier, forum, tier="C1"):
    agent = PoacClient("http://poac.test", http=verifier)
    receipt = agent.earn(tier, solver=solve)
    n = forum.get("/poac/nonce").json()
    assert n["audience"] == AUD and n["verifier"] == "http://poac.test"
    kb = agent.present(receipt, audience=n["audience"], nonce=n["nonce"])
    return agent, {"Authorization": f"PoAC {receipt.token}", "PoAC-KB": kb}


def test_gated_endpoint_end_to_end(verifier, forum):
    agent, headers = _earn_and_headers(verifier, forum)
    r = forum.post("/posts", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json() == {"ok": True, "by": agent.key.thumbprint, "tier": "C1"}
    # presentation is single-use: the same headers are refused the second time
    r2 = forum.post("/posts", headers=headers)
    assert r2.status_code == 401 and "already used" in r2.json()["detail"]


def test_missing_credentials_get_a_discoverable_challenge(forum):
    r = forum.post("/posts")
    assert r.status_code == 401
    www = r.headers["WWW-Authenticate"]
    assert www.startswith("PoAC ") and 'verifier="http://poac.test"' in www
    assert 'nonce="/poac/nonce"' in www and 'min_tier="C1"' in www


def test_tier_below_minimum_is_403(verifier, forum):
    _, headers = _earn_and_headers(verifier, forum, tier="C0")
    r = forum.post("/posts", headers=headers)
    assert r.status_code == 403 and "C0 below required C1" in r.json()["detail"]


def test_wrong_audience_rejected(verifier, forum):
    agent = PoacClient("http://poac.test", http=verifier)
    receipt = agent.earn("C1", solver=solve)
    nonce = forum.get("/poac/nonce").json()["nonce"]
    kb = agent.present(receipt, audience="https://other.example", nonce=nonce)
    r = forum.post("/posts", headers={"Authorization": f"PoAC {receipt.token}", "PoAC-KB": kb})
    assert r.status_code == 401 and "rejected" in r.json()["detail"]


def test_garbage_tokens_are_401_not_500(forum):
    r = forum.post("/posts", headers={"Authorization": "PoAC abc", "PoAC-KB": "not.a.jwt"})
    assert r.status_code == 401
    r = forum.post("/posts", headers={"Authorization": "Bearer x", "PoAC-KB": "a.b.c"})
    assert r.status_code == 401


def test_unbound_receipt_fails_identity_floor(verifier, forum):
    agent = PoacClient("http://poac.test", http=verifier)
    receipt = agent.earn("C1", solver=solve, bind_key=False)  # I0
    nonce = forum.get("/poac/nonce").json()["nonce"]
    kb = agent.present(receipt, audience=AUD, nonce=nonce)
    r = forum.post("/posts", headers={"Authorization": f"PoAC {receipt.token}", "PoAC-KB": kb})
    # verifier already refuses KB presentations for unbound receipts, or the gate's I1 floor does
    assert r.status_code in (401, 403)


# --- issuer pinning (H2) ------------------------------------------------------------
# A gate trusts exactly one verifier. Even if whatever answers /v1/verify says
# "valid", the receipt must name that verifier as `iss` and be signed under a
# `kid` from that verifier's JWKS.


def _lenient_verifier(jwks: dict) -> TestClient:
    """Stand-in for a compromised/typo'd verifier: says valid to everything."""
    app = FastAPI()

    @app.get("/v1/verify/nonce")
    def nonce():
        return {"nonce": "n", "expires_in": 60}

    @app.post("/v1/verify")
    def verify(body: dict):
        return {"valid": True, "capability_tier": "C3", "identity_tier": "I1"}

    @app.get("/.well-known/jwks.json")
    def keys():
        return jwks

    return TestClient(app)


def _gate_app(gate):
    app = FastAPI()
    app.include_router(gate.router)

    @app.post("/posts")
    def create_post(agent=Depends(gate.require)):
        return {"tier": agent.tier}

    return TestClient(app)


def test_receipt_from_other_issuer_refused_even_if_verify_says_valid(verifier):
    agent = PoacClient("http://poac.test", http=verifier)      # iss = http://poac.test
    receipt = agent.earn("C1", solver=solve)
    kb = agent.present(receipt, audience=AUD, nonce="n")
    headers = {"Authorization": f"PoAC {receipt.token}", "PoAC-KB": kb}

    lenient = _lenient_verifier(verifier.get("/.well-known/jwks.json").json())
    pinned_elsewhere = _gate_app(PoacGate(verifier_url="http://other.test", audience=AUD,
                                          http=lenient))
    r = pinned_elsewhere.post("/posts", headers=headers)
    assert r.status_code == 401 and "issuer mismatch" in r.json()["detail"]

    # same iss, but the signing kid is not in the pinned verifier's JWKS
    foreign = _lenient_verifier({"keys": []})
    r = _gate_app(PoacGate(verifier_url="http://poac.test", audience=AUD, http=foreign)) \
        .post("/posts", headers=headers)
    assert r.status_code == 401 and "unknown signing key" in r.json()["detail"]

    # iss and kid both match the pinned verifier: the lenient answer is accepted
    r = _gate_app(PoacGate(verifier_url="http://poac.test", audience=AUD, http=lenient)) \
        .post("/posts", headers=headers)
    assert r.status_code == 200 and r.json() == {"tier": "C3"}


def test_gate_refetches_jwks_once_on_unknown_kid(verifier):
    agent = PoacClient("http://poac.test", http=verifier)
    receipt = agent.earn("C1", solver=solve)
    kb = agent.present(receipt, audience=AUD, nonce="n")
    headers = {"Authorization": f"PoAC {receipt.token}", "PoAC-KB": kb}
    real_jwks = verifier.get("/.well-known/jwks.json").json()

    served = {"keys": []}          # rotated key not yet seen by the gate's cache
    lenient = _lenient_verifier(served)
    gate = PoacGate(verifier_url="http://poac.test", audience=AUD, http=lenient)
    forum = _gate_app(gate)
    assert forum.post("/posts", headers=headers).status_code == 401
    served["keys"] = real_jwks["keys"]        # verifier now publishes the new key
    assert forum.post("/posts", headers=headers).status_code == 200
