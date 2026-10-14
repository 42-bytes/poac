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
from poac.protocol.models import (
    CodeChallenge,
    DataChallenge,
    DiagramChallenge,
    LogicChallenge,
    NluChallenge,
    ProofChallenge,
)

_PAYLOADS = {
    "nlu": NluChallenge,
    "code": CodeChallenge,
    "logic": LogicChallenge,
    "data": DataChallenge,
    "diagram": DiagramChallenge,
    "proof": ProofChallenge,
}

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
    """Play one full session; returns pass/fail + per-round latency."""
    t_start = time.perf_counter()
    resp = http.post("/v1/sessions", json={"tier": tier})
    if resp.status_code == 429:
        time.sleep(2)
        resp = http.post("/v1/sessions", json={"tier": tier})
    if resp.status_code != 201:
        return {"passed": False, "error": f"http {resp.status_code}", "rounds": 0}
    data = resp.json()
    rnd = data["round"]
    round_latencies: list[float] = []
    families: list[str] = []
    client_errors: list[str] = []
    while True:
        fam = rnd["challenge"]["family"]
        families.append(fam)
        payload = _PAYLOADS[fam].model_validate(rnd["challenge"])
        t0 = time.perf_counter()
        try:
            answer = prover.answer(payload)
        except Exception as exc:  # noqa: BLE001 - recorded, not hidden
            answer = "solver-error"
            client_errors.append(f"{type(exc).__name__}: {str(exc)[:120]}")
        solve_ms = (time.perf_counter() - t0) * 1000
        resp = http.post(
            f"/v1/sessions/{data['session_id']}/rounds/{rnd['round_index']}",
            json={"nonce": rnd["nonce"], "answer": str(answer)[:2000]},
        )
        if resp.status_code != 200:
            return {"passed": False, "error": f"http {resp.status_code}", "rounds": len(round_latencies)}
        outcome = resp.json()
        round_latencies.append(solve_ms)
        if outcome["status"] == "next":
            rnd = outcome["round"]
            continue
        return {
            "passed": outcome["status"] == "passed",
            "failure": outcome.get("failure"),
            "families": families,
            "solve_ms": round_latencies,
            "session_ms": (time.perf_counter() - t_start) * 1000,
            "rounds": len(round_latencies),
            "client_errors": client_errors,
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
