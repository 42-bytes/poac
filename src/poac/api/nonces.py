"""Verifier-issued, one-shot, TTL-bounded nonces for ``POST /v1/verify``.

Why the verifier issues nonces (rather than accepting presenter-chosen ones):
freshness of a presentation then rests on something the verifier controls,
not on an ever-growing "seen" set that is lost on restart. Each nonce is
valid for a short window, consumed on first use (valid or not), and swept
when it expires — so memory is bounded by issue rate × TTL.
"""

from __future__ import annotations

import secrets
import threading
import time
from enum import Enum
from typing import Callable, Protocol

DEFAULT_NONCE_TTL_S = 120  # matches MAX_KB_AGE_S in presentation.py


class NonceState(str, Enum):
    fresh = "fresh"  # issued, unexpired, first use — accept
    used = "used"  # already consumed — replay
    unknown = "unknown"  # never issued, or expired and swept


class NonceStore(Protocol):
    def issue(self) -> tuple[str, int]:
        """Return (nonce, ttl_seconds)."""

    def consume(self, nonce: str) -> NonceState:
        """Mark the nonce used and report what it was before."""


class InMemoryNonceStore:
    def __init__(
        self,
        ttl_s: int = DEFAULT_NONCE_TTL_S,
        clock: Callable[[], float] = time.monotonic,
        max_outstanding: int = 100_000,
    ):
        self._ttl = ttl_s
        self._clock = clock
        self._max = max_outstanding
        # nonce -> (expires_at_monotonic, used)
        self._entries: dict[str, tuple[float, bool]] = {}
        self._lock = threading.Lock()

    def _sweep_locked(self, now: float) -> None:
        stale = [n for n, (exp, _) in self._entries.items() if exp <= now]
        for n in stale:
            del self._entries[n]

    def issue(self) -> tuple[str, int]:
        with self._lock:
            now = self._clock()
            self._sweep_locked(now)
            if len(self._entries) >= self._max:
                raise RuntimeError("nonce store at capacity, retry later")
            nonce = secrets.token_urlsafe(24)
            self._entries[nonce] = (now + self._ttl, False)
            return nonce, self._ttl

    def consume(self, nonce: str) -> NonceState:
        with self._lock:
            now = self._clock()
            entry = self._entries.get(nonce)
            if entry is None or entry[0] <= now:
                if entry is not None:
                    del self._entries[nonce]
                return NonceState.unknown
            exp, used = entry
            if used:
                return NonceState.used
            # keep the used marker until expiry so replays inside the window
            # are reported as `used`, not `unknown`
            self._entries[nonce] = (exp, True)
            return NonceState.fresh

    def __len__(self) -> int:  # for tests / metrics
        with self._lock:
            return len(self._entries)


class SqliteNonceStore:
    """Shared-by-replicas variant. Uses wall-clock time (comparable across
    hosts); each operation is a single atomic statement."""

    def __init__(
        self,
        path: str,
        ttl_s: int = DEFAULT_NONCE_TTL_S,
        clock: Callable[[], float] = time.time,
        busy_timeout_ms: int = 5_000,
    ):
        import sqlite3

        self._ttl = ttl_s
        self._clock = clock
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            path, check_same_thread=False, isolation_level=None,
            timeout=busy_timeout_ms / 1000,
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS verify_nonces ("
            " nonce TEXT PRIMARY KEY, expires_at REAL NOT NULL, used INTEGER NOT NULL)"
        )

    def issue(self) -> tuple[str, int]:
        now = self._clock()
        nonce = secrets.token_urlsafe(24)
        with self._lock:
            self._conn.execute("DELETE FROM verify_nonces WHERE expires_at <= ?", (now,))
            self._conn.execute(
                "INSERT INTO verify_nonces(nonce, expires_at, used) VALUES (?, ?, 0)",
                (nonce, now + self._ttl),
            )
        return nonce, self._ttl

    def consume(self, nonce: str) -> NonceState:
        now = self._clock()
        with self._lock:
            # atomic claim: only the first caller flips used 0 -> 1
            cur = self._conn.execute(
                "UPDATE verify_nonces SET used = 1"
                " WHERE nonce = ? AND used = 0 AND expires_at > ?",
                (nonce, now),
            )
            if cur.rowcount == 1:
                return NonceState.fresh
            row = self._conn.execute(
                "SELECT used FROM verify_nonces WHERE nonce = ? AND expires_at > ?",
                (nonce, now),
            ).fetchone()
        return NonceState.used if row else NonceState.unknown
