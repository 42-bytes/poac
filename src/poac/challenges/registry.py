"""Family registry and seeded challenge construction."""

from __future__ import annotations

import random

from poac.challenges import code, data, diagram, logic, nlu, proof
from poac.challenges.base import GeneratedChallenge, Generator

GENERATORS: dict[str, Generator] = {
    "nlu": nlu.generate,
    "code": code.generate,
    "logic": logic.generate,
    "data": data.generate,
    "diagram": diagram.generate,
    "proof": proof.generate,
}


def make_challenge(family: str, seed: bytes, difficulty: int) -> GeneratedChallenge:
    """Deterministically build a challenge instance from a seed.

    Same (family, seed, difficulty) always yields the identical challenge,
    which makes generation reproducible in tests while remaining
    unpredictable to clients (seeds derive from a server-secret HMAC chain).
    """
    if family not in GENERATORS:
        raise KeyError(f"unknown challenge family: {family}")
    rng = random.Random(int.from_bytes(seed, "big"))
    return GENERATORS[family](rng, max(0, min(difficulty, 3)))
