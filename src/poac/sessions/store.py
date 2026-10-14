"""Session stores: in-memory (single process) and SQLite (shared by replicas).

The orchestrator never touches a dict directly; it runs each operation
inside ``store.transaction()`` and reads/writes whole ``Session`` records.
For the in-memory store the transaction is a process lock; for SQLite it is
``BEGIN IMMEDIATE`` on a shared database file, which serialises replicas
against each other so a session created on one process can be continued on
another with the same one-time-use guarantees.

Replicas sharing a store must also share the server secret and issuer key
(see ``poac.api.cli``) and use a comparable clock (wall-clock, not
``time.monotonic``, which is per-host).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from typing import Iterator, Protocol

from poac.sessions.state import Session, session_from_dict, session_to_dict


class SessionStore(Protocol):
    def transaction(self) -> Iterator[None]: ...
    def get(self, session_id: str) -> Session | None: ...
    def put(self, session: Session) -> None: ...
    def delete(self, session_id: str) -> None: ...
    def count(self) -> int: ...
    def sweep(self, now: float) -> int:
        """Drop sessions whose ``expires_at`` <= now; return how many."""


class InMemorySessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    @contextmanager
    def transaction(self):
        with self._lock:
            yield

    def get(self, session_id: str) -> Session | None:
        return self._sessions.get(session_id)

    def put(self, session: Session) -> None:
        self._sessions[session.session_id] = session

    def delete(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def count(self) -> int:
        return len(self._sessions)

    def sweep(self, now: float) -> int:
        stale = [sid for sid, s in self._sessions.items() if s.expires_at <= now]
        for sid in stale:
            del self._sessions[sid]
        return len(stale)


class SqliteSessionStore:
    """One table, whole-record JSON. ``expires_at`` is indexed for sweeps."""

    def __init__(self, path: str, busy_timeout_ms: int = 5_000) -> None:
        self._path = path
        self._lock = threading.Lock()  # one transaction per process at a time
        self._conn = sqlite3.connect(
            path, check_same_thread=False, isolation_level=None, timeout=busy_timeout_ms / 1000
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS sessions ("
            " session_id TEXT PRIMARY KEY,"
            " expires_at REAL NOT NULL,"
            " data TEXT NOT NULL)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS sessions_expires ON sessions(expires_at)"
        )

    @contextmanager
    def transaction(self):
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def get(self, session_id: str) -> Session | None:
        row = self._conn.execute(
            "SELECT data FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        return None if row is None else session_from_dict(json.loads(row[0]))

    def put(self, session: Session) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO sessions(session_id, expires_at, data) VALUES (?, ?, ?)",
            (session.session_id, session.expires_at, json.dumps(session_to_dict(session))),
        )

    def delete(self, session_id: str) -> None:
        self._conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]

    def sweep(self, now: float) -> int:
        cur = self._conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        return cur.rowcount

    def close(self) -> None:
        self._conn.close()
