"""SQLite corpus of pre-authored instances with exposure accounting.

Every draw increments ``exposures``; an instance is retired once it reaches
``max_exposures`` or when its batch is retired by the operator (rotation).
Draws prefer the least-exposed instances so exposure is spread evenly.
"""

from __future__ import annotations

import json
import random
import sqlite3
import threading
import time
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, TypeAdapter

from poac.challenges.base import ChallengePayload, GeneratedChallenge
from poac.protocol.models import Challenge

_PAYLOAD = TypeAdapter(Challenge)


class CorpusInstance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    family: str
    difficulty: int
    payload: Challenge
    answer: str
    answer_format: str
    chain_material: str | None = None
    batch: str = "default"
    author: str = "unknown"

    def to_generated(self) -> GeneratedChallenge:
        return GeneratedChallenge(
            payload=self.payload, answer=self.answer,
            answer_format=self.answer_format, chain_material=self.chain_material,
        )


@dataclass(frozen=True)
class CorpusStats:
    active: int
    retired: int
    by_family: dict[tuple[str, int], int]  # (family, difficulty) -> active count
    exposures: int


class CorpusStore:
    def __init__(self, path: str, max_exposures: int = 5, busy_timeout_ms: int = 5_000):
        self._lock = threading.Lock()
        self._max = max_exposures
        self._conn = sqlite3.connect(
            path, check_same_thread=False, isolation_level=None,
            timeout=busy_timeout_ms / 1000,
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS corpus ("
            " id INTEGER PRIMARY KEY, family TEXT NOT NULL, difficulty INTEGER NOT NULL,"
            " data TEXT NOT NULL, batch TEXT NOT NULL, author TEXT NOT NULL,"
            " created_at REAL NOT NULL, exposures INTEGER NOT NULL DEFAULT 0,"
            " retired_at REAL)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS corpus_draw"
            " ON corpus(family, difficulty, retired_at, exposures)"
        )

    def close(self) -> None:
        self._conn.close()

    def add(self, inst: CorpusInstance) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO corpus(family, difficulty, data, batch, author, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (inst.family, inst.difficulty, inst.model_dump_json(), inst.batch,
                 inst.author, time.time()),
            )
            return cur.lastrowid

    def draw(self, family: str, difficulty: int, rng: random.Random) -> CorpusInstance | None:
        """Least-exposed active instance (random among ties), exposure += 1."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                rows = self._conn.execute(
                    "SELECT id, data, exposures FROM corpus"
                    " WHERE family = ? AND difficulty = ? AND retired_at IS NULL"
                    " AND exposures = (SELECT MIN(exposures) FROM corpus"
                    "   WHERE family = ? AND difficulty = ? AND retired_at IS NULL)",
                    (family, difficulty, family, difficulty),
                ).fetchall()
                if not rows:
                    self._conn.execute("COMMIT")
                    return None
                row_id, data, exposures = rng.choice(rows)
                retired = time.time() if exposures + 1 >= self._max else None
                self._conn.execute(
                    "UPDATE corpus SET exposures = exposures + 1, retired_at = ? WHERE id = ?",
                    (retired, row_id),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return CorpusInstance.model_validate_json(data)

    def retire_batch(self, batch: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE corpus SET retired_at = ? WHERE batch = ? AND retired_at IS NULL",
                (time.time(), batch),
            )
            return cur.rowcount

    def stats(self) -> CorpusStats:
        with self._lock:
            active = self._conn.execute(
                "SELECT COUNT(*) FROM corpus WHERE retired_at IS NULL").fetchone()[0]
            retired = self._conn.execute(
                "SELECT COUNT(*) FROM corpus WHERE retired_at IS NOT NULL").fetchone()[0]
            by = self._conn.execute(
                "SELECT family, difficulty, COUNT(*) FROM corpus WHERE retired_at IS NULL"
                " GROUP BY family, difficulty").fetchall()
            exp = self._conn.execute("SELECT COALESCE(SUM(exposures), 0) FROM corpus").fetchone()[0]
        return CorpusStats(
            active=active, retired=retired,
            by_family={(f, d): n for f, d, n in by}, exposures=exp,
        )

    def all_active(self) -> list[CorpusInstance]:
        with self._lock:
            rows = self._conn.execute("SELECT data FROM corpus WHERE retired_at IS NULL").fetchall()
        return [CorpusInstance.model_validate_json(r[0]) for r in rows]
