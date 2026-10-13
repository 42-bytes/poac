"""Prover clients for the evaluation harness.

Three classes of client, matching the threat-model profiles:

- ``ReferenceSolverClient`` — deterministic oracle with full source
  knowledge. Measures protocol overhead separate from model latency and
  empirically demonstrates limitation L2 (source-aware scripts can pass the
  template-generated prototype corpus).
- ``RandomGuessClient`` / ``KeywordHeuristicClient`` — deterministic script
  baselines *without* source knowledge (threat profile P3). Expected to fail
  at C1+; their measured pass rate feeds acceptance criterion 2.
- ``LlmAgentClient`` — provider-neutral structured-output agent built on
  PydanticAI (optional dependency; requires provider API keys). Feeds
  acceptance criterion 1 across model/provider configurations.
"""

from __future__ import annotations

import collections
import random
import re

from poac.protocol.models import (
    CodeChallenge,
    DataChallenge,
    DiagramChallenge,
    LogicChallenge,
    NluChallenge,
    ProofChallenge,
)
from poac.reference import solver as reference_solver

Payload = (
    NluChallenge
    | CodeChallenge
    | LogicChallenge
    | DataChallenge
    | DiagramChallenge
    | ProofChallenge
)

# Blind tactic spam: one submission that makes the kernel try each cheap
# tactic in turn. Passes trivial arithmetic (d0/d1) but cannot reference the
# challenge's recursive definitions, so induction goals (d2+) are out of
# reach without parsing the payload — which is the source-aware L2 profile.
BLIND_TACTIC_SPAM = "by first | decide | (intro n; omega) | (intro n; simp)"


class ReferenceSolverClient:
    name = "reference-solver"
    description = "source-aware deterministic oracle (demonstrates L2)"

    def answer(self, payload: Payload) -> str:
        return reference_solver.solve(payload)


class RandomGuessClient:
    name = "script-random"
    description = "blind deterministic script: random plausible guesses"

    def __init__(self, seed: int = 0):
        self._rng = random.Random(seed)

    def answer(self, payload: Payload) -> str:
        if isinstance(payload, ProofChallenge):
            return self._rng.choice(["by decide", "by rfl", "by simp"])
        if isinstance(payload, (CodeChallenge, DataChallenge, DiagramChallenge)):
            return str(self._rng.randint(0, 500))
        if isinstance(payload, NluChallenge):
            words = re.findall(r"[a-z]{4,}", payload.narrative)
            return self._rng.choice(words) if words else "unknown"
        words = re.findall(r"[A-Z][a-z]+", payload.statement)
        return self._rng.choice(words) if words else "unknown"


class KeywordHeuristicClient:
    name = "script-keyword"
    description = (
        "blind heuristic script: frequency/positional keyword extraction, "
        "no reasoning"
    )

    def answer(self, payload: Payload) -> str:
        if isinstance(payload, ProofChallenge):
            return BLIND_TACTIC_SPAM
        if isinstance(payload, NluChallenge):
            # most frequently mentioned lowercase entity — a classic shallow
            # heuristic that anti-parsing narrative design must defeat
            words = re.findall(r"\b[a-z]{4,}\b", payload.narrative)
            common = [
                w
                for w, _ in collections.Counter(words).most_common(10)
                if w not in {"that", "with", "this", "later", "which", "было"}
            ]
            return common[0] if common else "unknown"
        if isinstance(payload, LogicChallenge):
            names = re.findall(r"\b[A-Z][a-z]+\b", payload.statement)
            return collections.Counter(names).most_common(1)[0][0] if names else "unknown"
        if isinstance(payload, DataChallenge):
            # sum every units field: ignores all filters
            return str(sum(int(r.get("units", 0)) for r in payload.rows))
        if isinstance(payload, CodeChallenge):
            nums = re.findall(r"\d+", payload.source)
            return nums[-1] if nums else "0"
        nums = re.findall(r">(\d)</text>", payload.svg)
        return str(min(int(n) for n in nums) if nums else 0)


class LlmAgentClient:
    """Provider-neutral LLM agent using PydanticAI structured output.

    Requires the ``benchmarks`` extra (pydantic-ai-slim) and provider
    credentials in the environment. Model string examples:
    ``openai:gpt-5.2``, ``anthropic:claude-opus-4-6``, ``google:gemini-3-flash``.
    """

    description = "autonomous LLM agent (structured output, provider-neutral)"

    def __init__(self, model: str):
        from pydantic import BaseModel  # local import keeps core deps clean
        from pydantic_ai import Agent

        class Answer(BaseModel):
            answer: str

        self.name = f"llm:{model}"
        self._agent = Agent(
            model,
            output_type=Answer,
            instructions=(
                "You are completing a timed machine-capability challenge. "
                "Read the task and return ONLY the requested short answer in "
                "the `answer` field. No explanation."
            ),
        )

    def answer(self, payload: Payload) -> str:
        prompt = payload.model_dump_json()
        result = self._agent.run_sync(prompt)
        return result.output.answer
