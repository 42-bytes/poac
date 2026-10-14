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
    return TestClient(create_app(lean_bin=None, session_rate_per_minute=10_000))


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
