"""Lifetime counters: receipts issued (total, per tier) and sessions started.

They live in the session store so they survive restarts (SQLite) and are
exposed read-only at GET /v1/stats.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from poac.api.app import create_app
from poac.credentials.issuer import ReceiptIssuer
from poac.protocol.models import CapabilityTier, NextRoundResponse, SessionPassedResponse
from poac.reference.solver import solve
from poac.sessions.orchestrator import Orchestrator
from poac.sessions.store import InMemorySessionStore, SqliteSessionStore


class FakeClock:
    def __init__(self) -> None:
        self.t = 1_700_000_000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


def _pass(orch: Orchestrator, clock: FakeClock, tier: CapabilityTier) -> None:
    created = orch.create_session(tier, None)
    rnd, out = created.round, None
    while True:
        clock.advance(0.5)
        out = orch.submit(created.session_id, rnd.round_index, rnd.nonce, solve(rnd.challenge))
        if isinstance(out, NextRoundResponse):
            rnd = out.round
        else:
            break
    assert isinstance(out, SessionPassedResponse), out


def _fail(orch: Orchestrator, tier: CapabilityTier) -> None:
    created = orch.create_session(tier, None)
    orch.submit(created.session_id, created.round.round_index, created.round.nonce, "nope")


@pytest.mark.parametrize("make_store", [InMemorySessionStore, None])
def test_counters_track_receipts_and_sessions(tmp_path, make_store):
    store = make_store() if make_store else SqliteSessionStore(str(tmp_path / "s.db"))
    clock = FakeClock()
    o = Orchestrator(
        ReceiptIssuer.generate(issuer_url="https://poac.test"),
        server_secret=b"s" * 32, clock=clock, store=store,
    )
    assert o.counters() == {"receipts_issued": 0, "sessions_started": 0, "by_tier": {}}

    _pass(o, clock, CapabilityTier.C0)
    _pass(o, clock, CapabilityTier.C1)
    _pass(o, clock, CapabilityTier.C1)
    _fail(o, CapabilityTier.C1)  # started but no receipt

    c = o.counters()
    assert c["receipts_issued"] == 3
    assert c["sessions_started"] == 4
    assert c["by_tier"] == {"C0": 1, "C1": 2}


def test_sqlite_counters_survive_reopen(tmp_path):
    db = str(tmp_path / "s.db")
    clock = FakeClock()
    issuer = ReceiptIssuer.generate(issuer_url="https://poac.test")
    o = Orchestrator(issuer, server_secret=b"s" * 32, clock=clock, store=SqliteSessionStore(db))
    _pass(o, clock, CapabilityTier.C0)
    o.store.close()

    again = Orchestrator(issuer, server_secret=b"s" * 32, clock=clock, store=SqliteSessionStore(db))
    assert again.counters()["receipts_issued"] == 1


def test_stats_endpoint_is_public_and_cheap():
    app = create_app(orchestrator=Orchestrator(ReceiptIssuer.generate(), server_secret=b"s" * 32))
    r = TestClient(app).get("/v1/stats")
    assert r.status_code == 200
    body = r.json()
    assert body["receipts_issued"] == 0
    assert body["sessions_started"] == 0
    assert body["by_tier"] == {}
    assert r.headers["cache-control"].startswith("public")
