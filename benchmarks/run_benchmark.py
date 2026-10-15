"""Evaluation harness: run prover clients against the PoAC verifier.

Runs sessions either in-process (default; isolates protocol overhead) or
against a deployed ``--base-url`` (includes real network latency). Exports
anonymized aggregates as JSON for the gate report; no prover-identifying
data is recorded.

Examples:
    python -m benchmarks.run_benchmark --client reference --tier C1 --sessions 100
    python -m benchmarks.run_benchmark --client script-random --tier C1 --sessions 200
    python -m benchmarks.run_benchmark --client llm --model openai:gpt-5.2 --tier C1 --sessions 30
    python -m benchmarks.run_benchmark --client reference --tier C2 --sessions 50 --concurrency 8
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from benchmarks import clients as client_mod
from benchmarks.stats import percentiles, wilson_ci
from poac.api.app import create_app
from poac.client import PoacClient, PoacError, SessionFailed

REPORT_DIR = Path(__file__).resolve().parents[1] / "reports"


def make_client(kind: str, model: str | None):
    if kind == "reference":
        return client_mod.ReferenceSolverClient()
    if kind == "script-random":
        return client_mod.RandomGuessClient()
    if kind == "script-keyword":
        return client_mod.KeywordHeuristicClient()
    if kind == "llm":
        if not model:
            raise SystemExit("--model is required for --client llm")
        return client_mod.LlmAgentClient(model)
    raise SystemExit(f"unknown client kind: {kind}")


def run_session(http, prover, tier: str) -> dict:
    """Play one full session via ``poac.client``; returns pass/fail + per-round latency."""
    t_start = time.perf_counter()
    round_latencies: list[float] = []
    client_errors: list[str] = []

    def solver(challenge) -> str:
        try:
            return str(prover.answer(challenge))[:2000]
        except Exception as exc:  # noqa: BLE001 - recorded, not hidden
            client_errors.append(f"{type(exc).__name__}: {str(exc)[:120]}")
            return "solver-error"

    def on_round(_rnd, _answer, dt: float) -> None:
        round_latencies.append(dt * 1000)

    def usage() -> dict:
        # per-session token/cost attribution (exact at concurrency 1)
        calls = prover.drain_usage() if hasattr(prover, "drain_usage") else []
        costs = [c["cost_usd"] for c in calls if c.get("cost_usd") is not None]
        return {
            "input_tokens": sum(c["input_tokens"] or 0 for c in calls),
            "output_tokens": sum(c["output_tokens"] or 0 for c in calls),
            "cost_usd": sum(costs) if costs else None,
        }

    pc = PoacClient(base_url="", http=http)
    try:
        receipt = pc.earn(tier, solver, bind_key=False, on_round=on_round)
    except SessionFailed as sf:
        return {
            "passed": False, "failure": sf.failure.value, "families": sf.families,
            "solve_ms": round_latencies, "session_ms": (time.perf_counter() - t_start) * 1000,
            "rounds": len(round_latencies), "client_errors": client_errors, "usage": usage(),
        }
    except PoacError as pe:
        return {"passed": False, "error": str(pe)[:80], "rounds": len(round_latencies),
                "client_errors": client_errors, "usage": usage()}
    return {
        "passed": True, "failure": None, "families": receipt.families,
        "solve_ms": round_latencies, "session_ms": (time.perf_counter() - t_start) * 1000,
        "rounds": len(round_latencies), "client_errors": client_errors, "usage": usage(),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--client", required=True,
                    choices=["reference", "script-random", "script-keyword", "llm"])
    ap.add_argument("--model", help="PydanticAI model string for --client llm")
    ap.add_argument("--tier", default="C1", choices=["C0", "C1", "C2", "C3", "C4", "C5"])
    ap.add_argument("--sessions", type=int, default=20)
    ap.add_argument("--concurrency", type=int, default=1)
    ap.add_argument("--base-url", help="run against a deployed verifier instead of in-process")
    ap.add_argument("--corpus-db", help="in-process only: serve rounds from this private corpus "
                    "(exposure cap lifted so the benchmark does not retire instances)")
    args = ap.parse_args()

    prover = make_client(args.client, args.model)
    source = None
    if args.corpus_db:
        if args.base_url:
            raise SystemExit("--corpus-db applies to in-process runs; a deployed verifier has its own")
        from poac.corpus import CorpusSource, CorpusStore

        source = CorpusSource(CorpusStore(args.corpus_db, max_exposures=10**9))
    if args.base_url:
        http = httpx.Client(base_url=args.base_url, timeout=120)
        transport = "network"
    else:
        # in-process runs disable the ops rate limit so the harness measures
        # protocol behavior, not its own throttling
        orchestrator = None
        if source is not None:
            from poac.challenges.proof_check import find_lean
            from poac.credentials.issuer import ReceiptIssuer
            from poac.sessions.orchestrator import Orchestrator

            orchestrator = Orchestrator(ReceiptIssuer.generate(), lean_bin=find_lean(), source=source)
        http = TestClient(create_app(orchestrator=orchestrator, session_rate_per_minute=10_000_000))
        transport = "in-process+corpus" if source else "in-process"

    t0 = time.perf_counter()
    if args.concurrency > 1:
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            results = list(
                pool.map(lambda _: run_session(http, prover, args.tier), range(args.sessions))
            )
    else:
        results = [run_session(http, prover, args.tier) for _ in range(args.sessions)]
    wall_s = time.perf_counter() - t0

    passes = sum(1 for r in results if r.get("passed"))
    solve_ms = [ms for r in results for ms in r.get("solve_ms", [])]
    session_ms = [r["session_ms"] for r in results if "session_ms" in r]
    failures = [r.get("failure") or r.get("error") for r in results if not r.get("passed")]
    client_errors = [e for r in results for e in r.get("client_errors", [])]
    lo, hi = wilson_ci(passes, len(results))

    summary = {
        "client": prover.name,
        "client_description": prover.description,
        "tier": args.tier,
        "transport": transport,
        "sessions": len(results),
        "passes": passes,
        "pass_rate": passes / len(results),
        "pass_rate_wilson95": [round(lo, 4), round(hi, 4)],
        "failure_classes": dict(
            sorted(
                {f: failures.count(f) for f in set(failures)}.items()
            )
        ),
        # rounds where the prover itself raised (rate limits, provider errors);
        # these are submitted as wrong answers and inflate wrong_answer
        "client_error_rounds": len(client_errors),
        "client_errors_sample": sorted(set(client_errors))[:5],
        "solve_latency_ms": {k: round(v, 2) for k, v in percentiles(solve_ms).items()},
        "session_latency_ms": {k: round(v, 2) for k, v in percentiles(session_ms).items()},
        "mean_session_ms": round(statistics.fmean(session_ms), 2) if session_ms else None,
        "wall_clock_s": round(wall_s, 2),
        "concurrency": args.concurrency,
    }
    usages = [r["usage"] for r in results if r.get("usage")]
    costs = [u["cost_usd"] for u in usages if u.get("cost_usd") is not None]
    if usages and any(u["input_tokens"] or u["output_tokens"] for u in usages):
        total_cost = sum(costs) if costs else None
        summary["usage"] = {
            "input_tokens": sum(u["input_tokens"] for u in usages),
            "output_tokens": sum(u["output_tokens"] for u in usages),
            "sessions_with_cost": len(costs),
            "cost_usd_total": round(total_cost, 6) if total_cost is not None else None,
            "cost_usd_per_session": round(total_cost / len(usages), 6) if total_cost is not None else None,
            # what one receipt costs the agent operator, failed attempts included
            "cost_usd_per_receipt": (
                round(total_cost / passes, 6) if total_cost is not None and passes else None
            ),
        }
    if source is not None:
        summary["corpus"] = {
            "db": args.corpus_db, "rounds_served": source.served,
            "template_fallbacks": {f"{k[0]}/d{k[1]}": v for k, v in source.fallbacks.items()},
        }

    REPORT_DIR.mkdir(exist_ok=True)
    suffix = "-corpus" if source is not None else ""
    client_tag = args.client
    if args.client == "llm":
        client_tag = "llm-" + re.sub(r"[^A-Za-z0-9.]+", "-", args.model.split(":", 1)[-1])
    out = REPORT_DIR / f"bench-{client_tag}-{args.tier}{suffix}.json"
    out.write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    print(f"\nwritten to {out}")


if __name__ == "__main__":
    main()
