"""Abuse resistance: kernel-tier admission caps and bounded kernel concurrency."""

from __future__ import annotations

import threading
import time

import pytest

from poac.credentials.issuer import ReceiptIssuer
from poac.protocol.models import CapabilityTier
from poac.sessions import orchestrator as orch_mod
from poac.sessions.orchestrator import Orchestrator, SessionError
from poac.sessions.store import InMemorySessionStore, SqliteSessionStore


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def _orch(store=None, **kw):
    return Orchestrator(ReceiptIssuer.generate(), server_secret=b"s" * 32, clock=FakeClock(),
                        lean_bin="/nonexistent/lean", store=store, **kw)


@pytest.mark.parametrize("store_factory", [InMemorySessionStore, "sqlite"])
def test_active_kernel_sessions_are_capped(tmp_path, store_factory):
    store = SqliteSessionStore(str(tmp_path / "s.db")) if store_factory == "sqlite" else store_factory()
    o = _orch(store=store, max_kernel_sessions=2)
    o.create_session(CapabilityTier.C4, None)
    o.create_session(CapabilityTier.C5, None)
    with pytest.raises(SessionError, match="kernel tiers busy"):
        o.create_session(CapabilityTier.C4, None)
    # non-kernel tiers are unaffected by the kernel cap
    o.create_session(CapabilityTier.C1, None)
    assert store.count_kernel_active() == 2


def test_kernel_checks_run_at_most_n_at_a_time(monkeypatch):
    """check_proof is serialised through a semaphore of size kernel_slots."""
    running = 0
    peak = 0
    lock = threading.Lock()

    def slow_check(*a, **k):
        nonlocal running, peak
        with lock:
            running += 1
            peak = max(peak, running)
        time.sleep(0.05)
        with lock:
            running -= 1
        return orch_mod.ProofCheckResult(True, None)

    monkeypatch.setattr(orch_mod, "check_proof", slow_check)
    o = _orch(kernel_slots=2, max_kernel_sessions=10)
    sessions = [o.create_session(CapabilityTier.C4, None) for _ in range(6)]

    def go(created):
        o.submit(created.session_id, 1, created.round.nonce, "by decide")

    threads = [threading.Thread(target=go, args=(s,)) for s in sessions]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert peak <= 2
    assert o.kernel_queue_depth == 0


def test_kernel_slots_default_is_small():
    o = _orch()
    assert 1 <= o.kernel_slots <= 4
