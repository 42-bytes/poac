"""Formal logic family: ordering puzzles with a unique solution.

A hidden permutation of people is generated, natural-language constraints
consistent with it are added one at a time, and generation stops only when
brute-force enumeration over all permutations confirms exactly one solution.
"""

from __future__ import annotations

import random
from itertools import permutations

from poac.challenges.base import GeneratedChallenge
from poac.protocol.models import LogicChallenge

_NAMES = ["Priya", "Tomas", "Wei", "Amara", "Jonas", "Sofia", "Deniz", "Kofi"]


def _constraint_pool(order: tuple[str, ...]) -> list[tuple[str, "function"]]:
    """All (description, predicate) constraints satisfied by `order`."""
    pos = {name: i for i, name in enumerate(order)}
    k = len(order)
    pool: list[tuple[str, object]] = []

    def left_of(a: str, b: str):
        return lambda p: p.index(a) < p.index(b)

    def immediately_left(a: str, b: str):
        return lambda p: p.index(a) + 1 == p.index(b)

    def not_adjacent(a: str, b: str):
        return lambda p: abs(p.index(a) - p.index(b)) != 1

    def not_at(a: str, i: int):
        return lambda p: p.index(a) != i

    def at_edge(a: str):
        return lambda p: p.index(a) in (0, len(p) - 1)

    for a in order:
        for b in order:
            if a == b:
                continue
            if pos[a] < pos[b]:
                pool.append((f"{a} is somewhere to the left of {b}.", left_of(a, b)))
            if pos[a] + 1 == pos[b]:
                pool.append((f"{a} stands immediately to the left of {b}.", immediately_left(a, b)))
            if abs(pos[a] - pos[b]) != 1:
                pool.append((f"{a} is not standing next to {b}.", not_adjacent(a, b)))
    for a in order:
        if pos[a] in (0, k - 1):
            pool.append((f"{a} stands at one end of the line.", at_edge(a)))
        for i in range(k):
            if pos[a] != i:
                pool.append((f"{a} is not in position {i + 1}.", not_at(a, i)))
    return pool


def generate(rng: random.Random, difficulty: int) -> GeneratedChallenge:
    k = min(4 + difficulty, 6)
    names = rng.sample(_NAMES, k)
    order = tuple(rng.sample(names, k))

    pool = _constraint_pool(order)
    rng.shuffle(pool)

    chosen: list[tuple[str, object]] = []
    candidates = list(permutations(names))
    for desc, pred in pool:
        filtered = [p for p in candidates if pred(p)]
        if len(filtered) < len(candidates):
            chosen.append((desc, pred))
            candidates = filtered
        if len(candidates) == 1:
            break
    assert candidates == [order], "logic construction invariant violated"

    query_pos = rng.randrange(k)
    statement = (
        f"{k} people stand in a line at positions 1 (leftmost) through {k} "
        f"(rightmost): {', '.join(sorted(names))}. "
        + " ".join(desc for desc, _ in chosen)
    )
    question = (
        f"Who is in position {query_pos + 1}? Answer with the name only."
    )
    return GeneratedChallenge(
        payload=LogicChallenge(family="logic", statement=statement, question=question),
        answer=order[query_pos],
        answer_format="first name (single word)",
    )
