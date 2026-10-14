"""Authoring pipeline: spec -> render -> read back -> gate -> store.

Acceptance gates, all of which must pass:

1. ``readback == spec`` — an independent reader recovers exactly the hidden
   structure and the code-derived answer from the prose.
2. ``solve(payload) != answer`` — the public-template reference solver must
   fail (raise or answer wrongly), i.e. the surface form is not a template.
3. payload validates against the strict wire model.

Rejections are returned with reasons so authoring runs are debuggable.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from poac.challenges.base import answers_match
from poac.corpus.author import Author, payload_from_rendering
from poac.corpus.specs import ANSWER_FORMATS, check_readback, sample_spec
from poac.corpus.store import CorpusInstance, CorpusStore
from poac.reference.solver import solve


@dataclass
class BuildReport:
    family: str
    difficulty: int
    requested: int
    accepted: int = 0
    rejected: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"{self.family}/d{self.difficulty}: accepted {self.accepted}/{self.requested}"
            + (f", rejected {len(self.rejected)}" if self.rejected else "")
        )


def author_instance(
    author: Author, family: str, difficulty: int, rng: random.Random, batch: str
) -> tuple[CorpusInstance | None, str | None]:
    """One attempt. Returns (instance, None) or (None, reason)."""
    spec = sample_spec(family, rng, difficulty)
    try:
        rendering = author.render(spec, style_seed=rng.getrandbits(32))
        payload = payload_from_rendering(spec, rendering)
    except Exception as exc:  # noqa: BLE001 - author failures are data, not bugs
        return None, f"render failed: {type(exc).__name__}: {exc}"

    try:
        rb = author.readback(payload)
    except Exception as exc:  # noqa: BLE001
        return None, f"readback failed: {type(exc).__name__}: {exc}"
    errs = check_readback(spec, rb)
    if errs:
        return None, "readback mismatch: " + "; ".join(errs)

    try:
        if answers_match(solve(payload), spec.answer):
            return None, "solvable by public-template reference solver"
    except Exception:  # noqa: BLE001 - solver failing is the desired outcome
        pass

    inst = CorpusInstance(
        family=family, difficulty=difficulty, payload=payload, answer=spec.answer,
        answer_format=ANSWER_FORMATS[family], batch=batch, author=author.name,
    )
    return inst, None


def build(
    store: CorpusStore,
    author: Author,
    family: str,
    difficulty: int,
    count: int,
    batch: str = "default",
    seed: int | None = None,
    max_attempts_factor: int = 3,
) -> BuildReport:
    rng = random.Random(seed)
    report = BuildReport(family=family, difficulty=difficulty, requested=count)
    attempts = 0
    while report.accepted < count and attempts < count * max_attempts_factor:
        attempts += 1
        inst, reason = author_instance(author, family, difficulty, rng, batch)
        if inst is None:
            report.rejected.append(reason)
            continue
        store.add(inst)
        report.accepted += 1
    return report
