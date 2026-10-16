"""Append-only JSONL log of human-trial events + aggregate stats."""

from __future__ import annotations

import json
from importlib import resources
import statistics
import threading
import time
from pathlib import Path
from typing import Any

# Frontier-agent per-round solve p50 (ms), session pass rate, USD per receipt
# per tier — generated from reports/bench-llm-*.json by benchmarks/summarize.py.
_REF = json.loads(resources.files("poac.trials").joinpath("agent_reference.json").read_text("utf-8"))
AGENT_REFERENCE: dict[str, dict[str, dict[str, float]]] = _REF["models"]
AGENT_REFERENCE_NOTE: str = f"{_REF['note']} (measured {_REF['generated']})"


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
            "agents": {"solve_ms_p50": AGENT_REFERENCE, "note": AGENT_REFERENCE_NOTE},
        }
