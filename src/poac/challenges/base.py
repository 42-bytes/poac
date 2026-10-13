"""Shared challenge-generation primitives.

A generator is a pure function ``(rng, difficulty) -> GeneratedChallenge``:
same seed, same challenge. Verification is an exact match on the normalized
answer — no LLM is ever consulted at runtime.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable, Union

from poac.protocol.models import (
    CodeChallenge,
    DataChallenge,
    DiagramChallenge,
    LogicChallenge,
    NluChallenge,
    ProofChallenge,
)

ChallengePayload = Union[
    NluChallenge,
    CodeChallenge,
    LogicChallenge,
    DataChallenge,
    DiagramChallenge,
    ProofChallenge,
]


@dataclass(frozen=True)
class GeneratedChallenge:
    payload: ChallengePayload
    answer: str  # canonical answer (for proof: the reference proof)
    answer_format: str  # human/agent-readable hint, e.g. "integer"
    # what the next round's seed is chained on; defaults to `answer`.
    # The proof family chains on the proposition because submissions
    # are validated by the kernel and have no canonical text.
    chain_material: str | None = None


Generator = Callable[[random.Random, int], GeneratedChallenge]


def normalize_answer(raw: str) -> str:
    """Case-insensitive, whitespace-collapsed comparison form."""
    return " ".join(raw.strip().lower().split())


def answers_match(submitted: str, expected: str) -> bool:
    return normalize_answer(submitted) == normalize_answer(expected)
