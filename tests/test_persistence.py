"""Shared SQLite state (phase 2, task A4): two verifier replicas behave as one.

Replicas share the database file, server secret, issuer key and a
comparable clock. A session created on A must be continuable on B with the
same one-time-use guarantees, and the verify nonce issued by A must be
consumable exactly once on B.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from joserfc.jwk import OKPKey

from poac.api.app import create_app
from poac.api.nonces import NonceState, SqliteNonceStore
from poac.challenges import make_challenge
from poac.challenges.proof_check import find_lean
from poac.credentials.issuer import ReceiptIssuer
from poac.credentials.presentation import create_kb_jwt
from poac.protocol.models import (
    FAMILIES,
    CapabilityTier,
    FailureClass,
    HolderJwk,
    NextRoundResponse,
    SessionFailedResponse,
    SessionPassedResponse,
)
from poac.reference.solver import solve
from poac.sessions.config import TIERS
from poac.sessions.orchestrator import Orchestrator, SessionError
from poac.sessions.state import RoundState, Session, session_from_dict, session_to_dict
from poac.sessions.store import SqliteSessionStore

LEAN = find_lean()


class FakeClock:
    def __init__(self, t: float = 1_700_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def issuer():
    return ReceiptIssuer.generate(issuer_url="https://poac.test")


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "state.sqlite3")


def _replica(db, issuer, clock) -> Orchestrator:
    return Orchestrator(
        issuer, server_secret=b"shared" * 6, clock=clock,
        store=SqliteSessionStore(db), lean_bin=LEAN,
    )


# --- serialization -----------------------------------------------------------


@pytest.mark.parametrize("family", FAMILIES)
def test_session_round_trips_through_json_for_every_family(family):
    gc = make_challenge(family, b"\x03" * 32, 2)
    s = Session(
        session_id="sid", tier=CapabilityTier.C2, config=TIERS[CapabilityTier.C2],
        holder_jwk=HolderJwk(kty="OKP", crv="Ed25519", x="A" * 43),
        created_at=12.5, status="active", current_round=2,
        round_state=RoundState(
            family=family, expected_answer=gc.answer, nonce="n", issued_at=13.0,
            chain_material=gc.chain_material or gc.answer, payload=gc.payload,
            validating=family == "proof",
        ),
        families=["nlu", family], latencies_ms=[800], prev_answer_hash=b"\x07" * 32,
    )
    back = session_from_dict(session_to_dict(s))
    assert session_to_dict(back) == session_to_dict(s)
    assert back.round_state.payload == gc.payload
    assert back.config is TIERS[CapabilityTier.C2]


# --- sessions across replicas ------------------------------------------------


def test_session_created_on_a_continues_on_b_and_passes(db, issuer, clock):
    a, b = _replica(db, issuer, clock), _replica(db, issuer, clock)
    holder = OKPKey.generate_key("Ed25519")
    jwk = HolderJwk(kty="OKP", crv="Ed25519", x=holder.as_dict(private=False)["x"])
    created = a.create_session(CapabilityTier.C2, jwk)
    rnd, replicas, outcome = created.round, [b, a, b, a], None
    for i, r in enumerate(replicas):
        clock.advance(1.0)
        outcome = r.submit(created.session_id, rnd.round_index, rnd.nonce, solve(rnd.challenge))
        if isinstance(outcome, NextRoundResponse):
            rnd = outcome.round
        else:
            break
    assert isinstance(outcome, SessionPassedResponse), outcome
    assert outcome.identity_tier.value == "I1"
    assert len(outcome.latency_ms) == TIERS[CapabilityTier.C2].rounds


def test_replay_on_other_replica_is_rejected(db, issuer, clock):
    a, b = _replica(db, issuer, clock), _replica(db, issuer, clock)
    created = a.create_session(CapabilityTier.C1, None)
    rnd = created.round
    clock.advance(1.0)
    nxt = a.submit(created.session_id, 1, rnd.nonce, solve(rnd.challenge))
    assert isinstance(nxt, NextRoundResponse)
    # replaying round 1 on B: wrong round index now → protocol violation
    replay = b.submit(created.session_id, 1, rnd.nonce, solve(rnd.challenge))
    assert isinstance(replay, SessionFailedResponse)
    assert replay.failure is FailureClass.protocol_violation
    # and A sees the session as dead too
    with pytest.raises(SessionError, match="no longer active"):
        a.submit(created.session_id, 2, nxt.round.nonce, "x")


def test_session_survives_process_restart(db, issuer, clock):
    created = _replica(db, issuer, clock).create_session(CapabilityTier.C1, None)
    rnd = created.round
    clock.advance(1.0)
    fresh = _replica(db, issuer, clock)  # "restart": new orchestrator, same file
    outcome = fresh.submit(created.session_id, 1, rnd.nonce, solve(rnd.challenge))
    assert isinstance(outcome, NextRoundResponse)


def test_timing_is_enforced_across_replicas(db, issuer, clock):
    a, b = _replica(db, issuer, clock), _replica(db, issuer, clock)
    created = a.create_session(CapabilityTier.C1, None)
    clock.advance(TIERS[CapabilityTier.C1].round_deadline_ms / 1000 + 0.5)
    outcome = b.submit(created.session_id, 1, created.round.nonce, solve(created.round.challenge))
    assert isinstance(outcome, SessionFailedResponse)
    assert outcome.failure is FailureClass.timeout


def test_sqlite_sweep_and_capacity(db, issuer, clock):
    a = Orchestrator(
        issuer, server_secret=b"shared" * 6, clock=clock,
        store=SqliteSessionStore(db), max_sessions=2,
    )
    a.create_session(CapabilityTier.C0, None)
    a.create_session(CapabilityTier.C0, None)
    with pytest.raises(SessionError, match="capacity"):
        a.create_session(CapabilityTier.C0, None)
    assert a.store.count() == 2
    clock.advance(TIERS[CapabilityTier.C0].session_deadline_ms / 1000 + 61)
    a.create_session(CapabilityTier.C0, None)  # sweep ran first
    assert a.store.count() == 1


@pytest.mark.skipif(LEAN is None, reason="no Lean toolchain")
def test_kernel_round_validating_flag_is_shared(db, issuer, clock):
    """While A is running the kernel check, B must refuse a resubmission."""
    import threading

    from poac.sessions import orchestrator as orch_mod

    a, b = _replica(db, issuer, clock), _replica(db, issuer, clock)
    created = a.create_session(CapabilityTier.C4, None)
    rnd = created.round
    gate, seen = threading.Event(), {}
    real = orch_mod.check_proof

    def slow(*args, **kw):
        # B probes while A is inside the (lock-free) kernel phase
        try:
            b.submit(created.session_id, 1, rnd.nonce, solve(rnd.challenge))
        except SessionError as exc:
            seen["b"] = exc.message
        gate.set()
        return real(*args, **kw)

    orch_mod.check_proof = slow
    try:
        clock.advance(1.0)
        outcome = a.submit(created.session_id, 1, rnd.nonce, solve(rnd.challenge))
    finally:
        orch_mod.check_proof = real
    assert gate.is_set()
    assert "being validated" in seen["b"]
    assert isinstance(outcome, NextRoundResponse)


# --- verify nonces across replicas ------------------------------------------


def test_sqlite_nonce_store_shared(db, clock):
    a = SqliteNonceStore(db, ttl_s=120, clock=clock)
    b = SqliteNonceStore(db, ttl_s=120, clock=clock)
    nonce, ttl = a.issue()
    assert ttl == 120
    assert b.consume("never") is NonceState.unknown
    assert b.consume(nonce) is NonceState.fresh
    assert a.consume(nonce) is NonceState.used
    clock.advance(121)
    assert a.consume(nonce) is NonceState.unknown
    n2, _ = a.issue()  # issue sweeps expired rows
    assert a._conn.execute("SELECT COUNT(*) FROM verify_nonces").fetchone()[0] == 1


def test_full_http_flow_across_two_app_replicas(db, issuer):
    import time as _time

    def app():
        return create_app(
            issuer=issuer,
            orchestrator=Orchestrator(
                issuer, server_secret=b"shared" * 6, clock=_time.time,
                store=SqliteSessionStore(db), lean_bin=None,
            ),
            nonce_store=SqliteNonceStore(db),
        )

    ca, cb = TestClient(app()), TestClient(app())
    holder = OKPKey.generate_key("Ed25519")
    jwk = {k: v for k, v in holder.as_dict(private=False).items() if k in ("kty", "crv", "x")}
    data = ca.post("/v1/sessions", json={"tier": "C1", "holder_jwk": jwk}).json()
    rnd, clients, outcome = data["round"], [cb, ca, cb], None
    from tests.test_api import _parse_challenge

    for c in clients:
        outcome = c.post(
            f"/v1/sessions/{data['session_id']}/rounds/{rnd['round_index']}",
            json={"nonce": rnd["nonce"], "answer": solve(_parse_challenge(rnd))},
        ).json()
        if outcome["status"] == "next":
            rnd = outcome["round"]
    assert outcome["status"] == "passed"

    # nonce issued by A, presentation verified on B, replay rejected on A
    nonce = ca.get("/v1/verify/nonce").json()["nonce"]
    kb = create_kb_jwt(holder, outcome["receipt"], "https://rp", nonce)
    body = {"receipt": outcome["receipt"], "kb_jwt": kb, "audience": "https://rp", "nonce": nonce}
    assert cb.post("/v1/verify", json=body).json()["valid"] is True
    assert "already used" in ca.post("/v1/verify", json=body).json()["reason"]
