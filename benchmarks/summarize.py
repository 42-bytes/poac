"""Fold reports/bench-llm-*.json into the agent reference table the verifier
ships (src/poac/trials/agent_reference.json): per model and tier, the
median per-puzzle solve time, session pass rate, USD cost per receipt and
sessions measured. /play and / render it next to the human numbers.

    python -m benchmarks.summarize            # rewrite the JSON
    python -m benchmarks.summarize --print    # table to stdout only
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path

REPORT_DIR = Path(__file__).resolve().parents[1] / "reports"
OUT = Path(__file__).resolve().parents[1] / "src" / "poac" / "trials" / "agent_reference.json"

# OpenRouter id → label shown to people. Unknown ids fall back to the id.
LABELS = {
    "openai:gpt-6-astra": "GPT-6 Astra",
    "openai:gpt-6.1-sol": "GPT-6.1 Sol",
    "openai:gpt-6-luna": "GPT-6 Luna",
    "openai/gpt-5.6-sol": "GPT-5.6 Sol",
    "openai/gpt-5.6-luna": "GPT-5.6 Luna",
    "openai/gpt-5.6-terra": "GPT-5.6 Terra",
    "openai/gpt-5.5": "GPT-5.5",
    "openai/gpt-5-mini": "gpt-5-mini",
    "anthropic/claude-opus-5.5": "Claude Opus 5.5",
    "anthropic/claude-sonnet-5.5": "Claude Sonnet 5.5",
    "google/gemini-4-argon": "Gemini 4 Argon",
    "x-ai/grok-4.7": "Grok 4.7",
    "mistralai/mistral-large-4-0": "Mistral Large 4",
    "deepseek/deepseek-v4.1-flash": "DeepSeek V4.1 Flash",
    "qwen/qwen3.8-max-prime": "Qwen3.8 Max",
    "moonshotai/kimi-k3": "Kimi K3",
    "z-ai/glm-5.3-prime": "GLM-5.3",
    "minimax/minimax-m3": "MiniMax M3",
}
_FILE = re.compile(r"^bench-llm-(?P<model>.+)-(?P<tier>C[0-5])(?:-corpus)?\.json$")


def _model_id(tag: str) -> str:
    """Report filename tag back to an OpenRouter id (first '-' is the '/')."""
    for mid in LABELS:
        if re.sub(r"[^A-Za-z0-9.]+", "-", mid.split(":", 1)[-1]) == tag:
            return mid
    return tag


def summarize(report_dir: Path = REPORT_DIR) -> dict:
    table: dict[str, dict[str, dict]] = {}
    for f in sorted(report_dir.glob("bench-llm-*.json")):
        m = _FILE.match(f.name)
        if not m:
            continue
        r = json.loads(f.read_text())
        if r.get("sessions", 0) == 0 or r["sessions"] - r.get("client_error_rounds", 0) <= 0:
            continue  # provider errors, not the model
        mid = _model_id(m["tag"] if "tag" in m.groupdict() else m["model"])
        label = LABELS.get(mid, mid)
        entry = {
            "ms": round(r["solve_latency_ms"]["p50"]),
            "pass": round(r["pass_rate"], 3),
            "n": r["sessions"],
        }
        usage = r.get("usage") or {}
        if usage.get("cost_usd_per_receipt") is not None:
            entry["cost"] = round(usage["cost_usd_per_receipt"], 5)
        if usage.get("cost_usd_per_session") is not None:
            entry["cost_attempt"] = round(usage["cost_usd_per_session"], 5)
        table.setdefault(label, {})[m["tier"]] = entry
    return {
        "generated": date.today().isoformat(),
        "note": "one-shot LLM agents via OpenRouter, 2026-10 corpus; ms = median per puzzle, "
                "pass = session pass rate, cost = USD per receipt (failed attempts included)",
        "models": {k: dict(sorted(v.items())) for k, v in sorted(table.items())},
    }


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--print", action="store_true", help="do not write, just show")
    args = ap.parse_args(argv)
    ref = summarize()
    tiers = ["C1", "C2", "C3", "C4", "C5"]
    print(f"{'model':20}" + "".join(f"{t:>22}" for t in tiers))
    for name, by in ref["models"].items():
        cells = []
        for t in tiers:
            e = by.get(t)
            cells.append("-" if not e else f"{e['pass']*100:3.0f}% {e['ms']/1000:4.1f}s ${e.get('cost', 0):.4f}")
        print(f"{name:20}" + "".join(f"{c:>22}" for c in cells))
    if not args.print:
        OUT.write_text(json.dumps(ref, indent=1) + "\n")
        print(f"\nwritten to {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
