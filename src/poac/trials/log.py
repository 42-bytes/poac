"""Append-only JSONL log of human-trial events + aggregate stats."""

from __future__ import annotations

import json
import statistics
import threading
import time
from pathlib import Path
from typing import Any

# Frontier-agent per-round solve p50 at C1 against the 2026-10 corpus
# (reports/bench-llm-*-C1-corpus.json). Shown next to human numbers.
AGENT_REFERENCE_MS = {
    "GPT-5.5": 2883,
    "Gemini 4 Argon": 3132,
    "Claude Opus 5.5": 4421,
    "gpt-5-mini": 6029,
}


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return round(s[lo] + (s[hi] - s[lo]) * (k - lo), 1)


class TrialLog:
    """One JSON object per line. ``path=None`` keeps events in memory only
    (tests, throwaway instances)."""

    def __init__(self, path: str | Path | None):
        self.path = Path(path) if path else None
        self._mem: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: dict[str, Any]) -> None:
        event = {"ts": time.time(), **event}
        line = json.dumps(event, separators=(",", ":"))
        with self._lock:
            if self.path:
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
            else:
                self._mem.append(event)

    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            if not self.path:
                return list(self._mem)
            if not self.path.exists():
                return []
            return [json.loads(l) for l in self.path.read_text(encoding="utf-8").splitlines() if l]

    def stats(self) -> dict[str, Any]:
        ev = self.events()
        rounds = [e for e in ev if e.get("event") == "round"]
        sessions = [e for e in ev if e.get("event") == "session"]

        def agg(rs: list[dict[str, Any]]) -> dict[str, Any]:
            ms = [r["answer_ms"] for r in rs]
            scored = [r for r in rs if r.get("correct_if_untimed") is not None]
            return {
                "n": len(rs),
                "answer_ms_p10": _pct(ms, 0.1),
                "answer_ms_p50": _pct(ms, 0.5),
                "answer_ms_p90": _pct(ms, 0.9),
                "within_budget_rate": round(
                    sum(r["answer_ms"] <= r["budget_ms"] for r in rs) / len(rs), 3) if rs else None,
                "correct_if_untimed_rate": round(
                    sum(bool(r["correct_if_untimed"]) for r in scored) / len(scored), 3)
                if scored else None,
                "correct_in_time_rate": round(
                    sum(r["outcome"] == "correct" for r in rs) / len(rs), 3) if rs else None,
            }

        def group(key: str) -> dict[str, Any]:
            out: dict[str, list] = {}
            for r in rounds:
                out.setdefault(str(r.get(key)), []).append(r)
            return {k: agg(v) for k, v in sorted(out.items())}

        # per-session mean answer time, by mode (anonymous; capped so the
        # payload stays small as the log grows)
        per_session: dict[str, dict[str, list[float]]] = {}
        for r in rounds:
            per_session.setdefault(str(r.get("mode")), {}).setdefault(r["session_id"], []).append(r["answer_ms"])
        session_avg_ms = {
            mode: sorted(round(sum(v) / len(v)) for v in by_sid.values())[-5000:]
            for mode, by_sid in sorted(per_session.items())
        }

        return {
            "sessions": len(sessions),
            "sessions_passed": sum(s.get("status") == "passed" for s in sessions),
            "session_avg_ms": session_avg_ms,
            "rounds": len(rounds),
            "by_family": group("family"),
            "by_mode": group("mode"),
            "by_tier": group("tier"),
            "by_family_and_mode": {
                k: agg([r for r in rounds if f"{r['family']}/{r['mode']}" == k])
                for k in sorted({f"{r['family']}/{r['mode']}" for r in rounds})
            },
            "agents": {"solve_ms_p50_at_C1": AGENT_REFERENCE_MS,
                       "note": "frontier agents, one-shot, 2026-10 corpus"},
        }
