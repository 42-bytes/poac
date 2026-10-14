"""Production remedies from the red-team pass (phase 2, task A2).

1. verifier-issued one-shot nonces for /v1/verify (presenter-chosen rejected);
2. bounded memory: nonce store and rate limiter expire their entries;
3. a crash inside the Lean kernel call voids the session instead of leaving
   the round stuck in `validating`.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from joserfc.jwk import OKPKey

from poac.api.app import _RateLimiter, create_app
from poac.api.nonces import InMemoryNonceStore, NonceState
from poac.credentials.issuer import ReceiptIssuer
from poac.credentials.presentation import create_kb_jwt
from poac.protocol.models import CapabilityTier, HolderJwk, IdentityTier
from poac.sessions import orchestrator as orch_mod
from poac.sessions.orchestrator import Orchestrator, SessionError, VerifierError


class FakeClock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


# --- 1. verifier-issued nonces ------------------------------------------------


def test_nonce_store_lifecycle():
    clock = FakeClock()
    store = InMemoryNonceStore(ttl_s=120, clock=clock)
    nonce, ttl = store.issue()
    assert ttl == 120
    assert store.consume("never-issued") is NonceState.unknown
    assert store.consume(nonce) is NonceState.fresh
    assert store.consume(nonce) is NonceState.used  # replay inside window
    clock.advance(121)
    assert store.consume(nonce) is NonceState.unknown  # expired → forgotten


def test_nonce_store_memory_is_bounded_by_ttl():
    clock = FakeClock()
    store = InMemoryNonceStore(ttl_s=10, clock=clock)
    for _ in range(500):
        store.issue()
    assert len(store) == 500
    clock.advance(11)
    store.issue()  # any issue() sweeps expired entries
    assert len(store) == 1


def test_nonce_store_capacity_guard():
    store = InMemoryNonceStore(max_outstanding=3)
    for _ in range(3):
        store.issue()
    with pytest.raises(RuntimeError, match="capacity"):
        store.issue()


def _issue_receipt(issuer: ReceiptIssuer, holder_key: OKPKey) -> str:
    x = holder_key.as_dict(private=False)["x"]
    return issuer.issue(
        session_id="s-h",
        capability_tier=CapabilityTier.C1,
        identity_tier=IdentityTier.I1,
        families=["nlu"],
        latencies_ms=[500],
        rounds_total=1,
        receipt_ttl_s=300,
        holder_jwk=HolderJwk(kty="OKP", crv="Ed25519", x=x),
    )


def test_verify_rejects_presenter_chosen_nonce():
    issuer = ReceiptIssuer.generate(issuer_url="http://testserver")
    client = TestClient(create_app(issuer=issuer, lean_bin=None))
    holder = OKPKey.generate_key("Ed25519")
    receipt = _issue_receipt(issuer, holder)
    kb = create_kb_jwt(holder, receipt, "aud", "my-own-nonce")
    resp = client.post(
        "/v1/verify",
        json={"receipt": receipt, "kb_jwt": kb, "audience": "aud", "nonce": "my-own-nonce"},
    )
    body = resp.json()
    assert body["valid"] is False
    assert "not issued" in body["reason"]


def test_verify_nonce_is_consumed_even_when_presentation_fails():
    """A failed attempt must not leave the nonce reusable for a second try."""
    issuer = ReceiptIssuer.generate(issuer_url="http://testserver")
    client = TestClient(create_app(issuer=issuer, lean_bin=None))
    holder = OKPKey.generate_key("Ed25519")
    receipt = _issue_receipt(issuer, holder)
    nonce = client.get("/v1/verify/nonce").json()["nonce"]

    # first attempt: wrong audience → invalid, but nonce burned
    kb_bad = create_kb_jwt(holder, receipt, "wrong-aud", nonce)
    r1 = client.post(
        "/v1/verify",
        json={"receipt": receipt, "kb_jwt": kb_bad, "audience": "aud", "nonce": nonce},
    ).json()
    assert r1["valid"] is False and "audience" in r1["reason"]

    # second attempt with a correct KB but the same nonce → replay
    kb_good = create_kb_jwt(holder, receipt, "aud", nonce)
    r2 = client.post(
        "/v1/verify",
        json={"receipt": receipt, "kb_jwt": kb_good, "audience": "aud", "nonce": nonce},
    ).json()
    assert r2["valid"] is False and "already used" in r2["reason"]


def test_verify_nonce_endpoint_shape_and_uniqueness():
    client = TestClient(create_app(lean_bin=None))
    a = client.get("/v1/verify/nonce").json()
    b = client.get("/v1/verify/nonce").json()
    assert set(a) == {"nonce", "expires_in"}
    assert a["expires_in"] > 0
    assert a["nonce"] != b["nonce"]


# --- 2. rate limiter memory --------------------------------------------------


def test_rate_limiter_forgets_previous_minutes():
    clock = FakeClock(t=0.0)
    limiter = _RateLimiter(limit_per_minute=5, clock=clock)
    for i in range(1000):
        assert limiter.allow(f"client-{i}")
    assert len(limiter) == 1000
    clock.advance(60)
    assert limiter.allow("fresh-client")
    assert len(limiter) == 1  # everything from the previous minute dropped


def test_rate_limiter_still_limits_within_minute():
    clock = FakeClock(t=0.0)
    limiter = _RateLimiter(limit_per_minute=3, clock=clock)
    assert [limiter.allow("c") for _ in range(4)] == [True, True, True, False]
    clock.advance(60)
    assert limiter.allow("c")  # new window


# --- 3. kernel crash voids the session cleanly -------------------------------


def test_kernel_exception_voids_session_instead_of_wedging(monkeypatch):
    """Simulate the Lean subprocess blowing up (binary vanished, OSError…)."""
    from poac.protocol.models import ProofChallenge

    clock = FakeClock()
    orch = Orchestrator(
        ReceiptIssuer.generate(), server_secret=b"k" * 32, clock=clock,
        lean_bin="/definitely/not/lean",
    )
    created = orch.create_session(CapabilityTier.C4, None)
    assert isinstance(created.round.challenge, ProofChallenge)

    def boom(*_a, **_k):
        raise FileNotFoundError("lean binary missing")

    monkeypatch.setattr(orch_mod, "check_proof", boom)
    clock.advance(1.0)
    with pytest.raises(VerifierError, match="voided"):
        orch.submit(created.session_id, 1, created.round.nonce, "by decide")

    # not wedged: a resubmission is a clean "no longer active", not
    # "being validated"
    with pytest.raises(SessionError, match="no longer active"):
        orch.submit(created.session_id, 1, created.round.nonce, "by decide")
    session = orch.store.get(created.session_id)
    assert session.status == "failed" and session.round_state is None


def test_kernel_exception_surfaces_as_503_over_http(monkeypatch):
    client = TestClient(create_app(lean_bin="/definitely/not/lean"))
    data = client.post("/v1/sessions", json={"tier": "C4"}).json()

    def boom(*_a, **_k):
        raise OSError("sandbox exploded")

    monkeypatch.setattr(orch_mod, "check_proof", boom)
    resp = client.post(
        f"/v1/sessions/{data['session_id']}/rounds/1",
        json={"nonce": data["round"]["nonce"], "answer": "by decide"},
    )
    assert resp.status_code == 503
    assert "voided" in resp.json()["detail"]
