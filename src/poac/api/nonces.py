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
