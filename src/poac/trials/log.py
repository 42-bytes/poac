"""Append-only JSONL log of human-trial events + aggregate stats."""

from __future__ import annotations

import json
import statistics
import threading
import time
from pathlib import Path
from typing import Any

# Frontier-agent per-round solve p50 (ms) and session pass rate per tier,
# from reports/bench-llm-*-C{n}[-corpus].json (2026-10 corpus; C4/C5 are the
# Lean proof tiers, not offered to humans). Shown next to human numbers.
AGENT_REFERENCE: dict[str, dict[str, dict[str, float]]] = {
    "GPT-5.5": {"C1": {"ms": 2883, "pass": 1.0}, "C2": {"ms": 3685, "pass": 1.0}, "C3": {"ms": 3504, "pass": 0.9},
                "C4": {"ms": 12606, "pass": 0.0}, "C5": {"ms": 4384, "pass": 0.4}},
    "Gemini 4 Argon": {"C1": {"ms": 3132, "pass": 1.0}, "C2": {"ms": 3682, "pass": 1.0}, "C3": {"ms": 4306, "pass": 1.0},
                       "C4": {"ms": 2446, "pass": 1.0}, "C5": {"ms": 4249, "pass": 1.0}},
    "Claude Opus 5.5": {"C1": {"ms": 4421, "pass": 1.0}, "C2": {"ms": 5202, "pass": 1.0}, "C3": {"ms": 5418, "pass": 1.0},
                        "C4": {"ms": 7197, "pass": 1.0}, "C5": {"ms": 5501, "pass": 1.0}},
    "gpt-5-mini": {"C1": {"ms": 6029, "pass": 1.0}, "C2": {"ms": 7701, "pass": 0.77}},
    "Grok 4.7": {"C1": {"ms": 7171, "pass": 0.7}, "C2": {"ms": 8482, "pass": 0.3}, "C3": {"ms": 26254, "pass": 0.0}},
}


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return round(s[lo] + (s[hi] - s[lo]) * (k - lo), 1)


def purge_source(path: str | Path, src: str | None = None, net: str | None = None) -> int:
    """Drop every row tagged with this `src` and/or `net`; return how many.

    Rewrites the file atomically. The operator runs this after spotting a
    spamming source in the stats (see `poac-trials purge`).
    """
    path = Path(path)
    if not path.exists() or (src is None and net is None):
        return 0
    kept, removed = [], 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        row = json.loads(line)
        if (src is not None and row.get("src") == src) or (net is not None and row.get("net") == net):
            removed += 1
        else:
            kept.append(line)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("".join(l + "\n" for l in kept), encoding="utf-8")
    tmp.replace(path)
    return removed


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

        # Only correct answers count as times: a fast wrong answer says nothing
        # about how long the puzzle takes. Accuracy rates still use every round.
        def timed(r: dict[str, Any]) -> bool:
            return bool(r.get("correct_if_untimed"))

        def agg(rs: list[dict[str, Any]]) -> dict[str, Any]:
            ms = [r["answer_ms"] for r in rs if timed(r)]
            scored = [r for r in rs if r.get("correct_if_untimed") is not None]
            return {
                "n": len(rs),
                "n_timed": len(ms),
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

        # per-session mean time over correct answers, by mode and tier
        # (anonymous; capped so the payload stays small as the log grows);
        # a session with no correct answer has no time
        per_session: dict[str, dict[str, dict[str, list[float]]]] = {}
        for r in rounds:
            if not timed(r):
                continue
            (per_session.setdefault(str(r.get("mode")), {})
             .setdefault(str(r.get("tier")), {})
             .setdefault(r["session_id"], []).append(r["answer_ms"]))
        session_avg_ms = {
            mode: {tier: sorted(round(sum(v) / len(v)) for v in by_sid.values())[-5000:]
                   for tier, by_sid in sorted(by_tier.items())}
            for mode, by_tier in sorted(per_session.items())
        }

        def pair_group(a: str, b: str) -> dict[str, Any]:
            keys = sorted({f"{r[a]}/{r[b]}" for r in rounds})
            return {k: agg([r for r in rounds if f"{r[a]}/{r[b]}" == k]) for k in keys}

        return {
            "sessions": len(sessions),
            "sessions_passed": sum(s.get("status") == "passed" for s in sessions),
            "session_avg_ms": session_avg_ms,
            "rounds": len(rounds),
            "by_family": group("family"),
            "by_mode": group("mode"),
            "by_tier": group("tier"),
            "by_family_and_mode": pair_group("family", "mode"),
            "by_tier_and_mode": pair_group("tier", "mode"),
            "agents": {"solve_ms_p50": AGENT_REFERENCE,
                       "note": "frontier agents, one-shot per tier, 2026-10 corpus; ms = median per puzzle, pass = session pass rate"},
        }
