"""Code-tracing family.

Generates a small Python program from a fixed grammar (integer arithmetic,
loops, conditionals) and asks for its printed output. The program is built
as a list of structured blocks; the same blocks are (a) rendered to source
text and (b) interpreted directly to compute the expected answer, so no
dynamic code execution is involved anywhere.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from poac.challenges.base import GeneratedChallenge
from poac.protocol.models import CodeChallenge

_VARS = ["acc", "total", "value", "count", "result"]
_WORDS = ["antiphon", "vermilion", "quandary", "isthmus", "obelisk"]


@dataclass(frozen=True)
class _LoopAdd:
    a: int
    b: int
    step: int
    mult: int


@dataclass(frozen=True)
class _LoopMulMod:
    a: int
    b: int
    mod: int


@dataclass(frozen=True)
class _Cond:
    pivot: int
    delta_hi: int
    delta_lo: int


@dataclass(frozen=True)
class _StrLen:
    word: str
    k: int


_Block = _LoopAdd | _LoopMulMod | _Cond | _StrLen


def _random_block(rng: random.Random) -> _Block:
    kind = rng.choice(["loop_add", "loop_mul_mod", "cond", "str_len"])
    if kind == "loop_add":
        return _LoopAdd(rng.randint(1, 4), rng.randint(6, 12), rng.choice([1, 2, 3]), rng.randint(2, 5))
    if kind == "loop_mul_mod":
        return _LoopMulMod(rng.randint(2, 4), rng.randint(5, 8), rng.choice([97, 101, 251, 397]))
    if kind == "cond":
        return _Cond(rng.randint(10, 200), rng.randint(3, 40), rng.randint(3, 40))
    return _StrLen(rng.choice(_WORDS), rng.randint(1, 3))


def _render(var: str, start: int, blocks: list[_Block]) -> str:
    lines = [f"{var} = {start}"]
    for blk in blocks:
        if isinstance(blk, _LoopAdd):
            lines += [
                f"for i in range({blk.a}, {blk.b}, {blk.step}):",
                f"    {var} += i * {blk.mult}",
            ]
        elif isinstance(blk, _LoopMulMod):
            lines += [
                f"for i in range({blk.a}, {blk.b}):",
                f"    {var} = ({var} * i) % {blk.mod}",
            ]
        elif isinstance(blk, _Cond):
            lines += [
                f"if {var} > {blk.pivot}:",
                f"    {var} -= {blk.delta_hi}",
                "else:",
                f"    {var} += {blk.delta_lo}",
            ]
        else:
            lines.append(f"{var} += len('{blk.word}' * {blk.k})")
    lines.append(f"print({var})")
    return "\n".join(lines)


def _interpret(start: int, blocks: list[_Block]) -> int:
    value = start
    for blk in blocks:
        if isinstance(blk, _LoopAdd):
            for i in range(blk.a, blk.b, blk.step):
                value += i * blk.mult
        elif isinstance(blk, _LoopMulMod):
            for i in range(blk.a, blk.b):
                value = (value * i) % blk.mod
        elif isinstance(blk, _Cond):
            value = value - blk.delta_hi if value > blk.pivot else value + blk.delta_lo
        else:
            value += len(blk.word) * blk.k
    return value


def generate(rng: random.Random, difficulty: int) -> GeneratedChallenge:
    var = rng.choice(_VARS)
    start = rng.randint(1, 9)
    blocks = [_random_block(rng) for _ in range(2 + difficulty)]
    source = _render(var, start, blocks)
    answer = str(_interpret(start, blocks))
    return GeneratedChallenge(
        payload=CodeChallenge(
            family="code",
            language="python",
            source=source,
            question="What exact value does this program print? Answer with the value only.",
        ),
        answer=answer,
        answer_format="integer",
    )
