"""Hidden structure behind a corpus instance, and the answer derived from it.

A *spec* is what the verifier knows and the author never chooses: entities,
facts, constraints, the question target. The author (LLM) only turns a spec
into prose. ``check_readback`` compares what an independent reader
extracted from that prose against the spec; any discrepancy rejects the
rendering, so a hallucinated or ambiguous narrative never enters the corpus.
"""

from __future__ import annotations

import random
from itertools import permutations
from typing import Literal, Union

from pydantic import BaseModel, ConfigDict, Field

from poac.challenges import data as _data
from poac.challenges import logic as _logic
from poac.challenges import nlu as _nlu

CORPUS_FAMILIES: tuple[str, ...] = ("nlu", "logic", "data")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --- nlu ----------------------------------------------------------------------


class NodeFact(_Model):
    name: str
    day: int = Field(ge=1, le=28)
    checksum: Literal["match", "mismatch"]
    site: str
    engineer: str


class NluSpec(_Model):
    family: Literal["nlu"] = "nlu"
    nodes: list[NodeFact]
    cutoff: int
    red_herring: str
    n_filler: int

    @property
    def answer(self) -> str:
        (t,) = [n.name for n in self.nodes if n.day < self.cutoff and n.checksum == "mismatch"]
        return t


class NluReadback(_Model):
    """What an independent reader extracted from the narrative."""

    facts: list[NodeFact]
    cutoff: int
    answer: str


def sample_nlu(rng: random.Random, difficulty: int) -> NluSpec:
    n_candidates = min(4 + difficulty, 7)
    nodes = rng.sample(_nlu._NODE_NAMES, n_candidates)
    cutoff = rng.randint(10, 20)
    target = rng.choice(nodes)
    facts = []
    for node in nodes:
        if node == target:
            day, checksum = rng.randint(1, cutoff - 1), "mismatch"
        elif rng.random() < 0.5:
            day, checksum = rng.randint(cutoff, 28), rng.choice(["match", "mismatch"])
        else:
            day, checksum = rng.randint(1, cutoff - 1), "match"
        facts.append(NodeFact(
            name=node, day=day, checksum=checksum,
            site=rng.choice(_nlu._SITES), engineer=rng.choice(_nlu._ENGINEERS),
        ))
    spec = NluSpec(
        nodes=facts, cutoff=cutoff,
        red_herring=rng.choice([n for n in nodes if n != target]),
        n_filler=2 + 2 * difficulty,
    )
    assert spec.answer == target
    return spec


def _check_nlu(spec: NluSpec, rb: NluReadback) -> list[str]:
    errs = []
    if rb.cutoff != spec.cutoff:
        errs.append(f"cutoff {rb.cutoff} != {spec.cutoff}")
    want = {n.name: n for n in spec.nodes}
    got = {n.name: n for n in rb.facts}
    if set(want) != set(got):
        errs.append(f"nodes {sorted(got)} != {sorted(want)}")
    for name in set(want) & set(got):
        for f in ("day", "checksum", "site"):
            if getattr(want[name], f) != getattr(got[name], f):
                errs.append(f"{name}.{f}: {getattr(got[name], f)!r} != {getattr(want[name], f)!r}")
    if rb.answer != spec.answer:
        errs.append(f"answer {rb.answer!r} != {spec.answer!r}")
    return errs


# --- logic --------------------------------------------------------------------


class Constraint(_Model):
    kind: Literal["left_of", "immediately_left", "not_adjacent", "not_at", "at_edge"]
    a: str
    b: str | None = None
    position: int | None = Field(default=None, ge=1)  # 1-based, for not_at

    def holds(self, p: tuple[str, ...]) -> bool:
        if self.kind == "left_of":
            return p.index(self.a) < p.index(self.b)
        if self.kind == "immediately_left":
            return p.index(self.a) + 1 == p.index(self.b)
        if self.kind == "not_adjacent":
            return abs(p.index(self.a) - p.index(self.b)) != 1
        if self.kind == "not_at":
            return p.index(self.a) != self.position - 1
        return p.index(self.a) in (0, len(p) - 1)

    def key(self) -> tuple:
        return (self.kind, self.a, self.b, self.position)


class LogicSpec(_Model):
    family: Literal["logic"] = "logic"
    names: list[str]  # sorted, as presented
    order: list[str]  # hidden solution, left to right
    constraints: list[Constraint]
    query_position: int = Field(ge=1)

    @property
    def answer(self) -> str:
        return self.order[self.query_position - 1]

    def unique_solution(self) -> bool:
        sols = [p for p in permutations(self.names) if all(c.holds(p) for c in self.constraints)]
        return sols == [tuple(self.order)]


class LogicReadback(_Model):
    names: list[str]
    constraints: list[Constraint]
    query_position: int
    answer: str


def sample_logic(rng: random.Random, difficulty: int) -> LogicSpec:
    k = min(4 + difficulty, 6)
    names = rng.sample(_logic._NAMES, k)
    order = tuple(rng.sample(names, k))
    pos = {n: i for i, n in enumerate(order)}
    pool: list[Constraint] = []
    for a in order:
        for b in order:
            if a == b:
                continue
            if pos[a] < pos[b]:
                pool.append(Constraint(kind="left_of", a=a, b=b))
            if pos[a] + 1 == pos[b]:
                pool.append(Constraint(kind="immediately_left", a=a, b=b))
            if abs(pos[a] - pos[b]) != 1:
                pool.append(Constraint(kind="not_adjacent", a=a, b=b))
        if pos[a] in (0, k - 1):
            pool.append(Constraint(kind="at_edge", a=a))
        for i in range(k):
            if pos[a] != i:
                pool.append(Constraint(kind="not_at", a=a, position=i + 1))
    rng.shuffle(pool)
    chosen, candidates = [], list(permutations(names))
    for c in pool:
        filtered = [p for p in candidates if c.holds(p)]
        if len(filtered) < len(candidates):
            chosen.append(c)
            candidates = filtered
        if len(candidates) == 1:
            break
    spec = LogicSpec(
        names=sorted(names), order=list(order), constraints=chosen,
        query_position=rng.randrange(k) + 1,
    )
    assert spec.unique_solution()
    return spec


def _check_logic(spec: LogicSpec, rb: LogicReadback) -> list[str]:
    errs = []
    if sorted(rb.names) != spec.names:
        errs.append(f"names {sorted(rb.names)} != {spec.names}")
    want = {c.key() for c in spec.constraints}
    got = {c.key() for c in rb.constraints}
    if want != got:
        errs.append(f"constraints missing={sorted(want - got)} extra={sorted(got - want)}")
    if rb.query_position != spec.query_position:
        errs.append(f"query_position {rb.query_position} != {spec.query_position}")
    if rb.answer != spec.answer:
        errs.append(f"answer {rb.answer!r} != {spec.answer!r}")
    return errs


# --- data ---------------------------------------------------------------------


class DataSpec(_Model):
    family: Literal["data"] = "data"
    rows: list[dict[str, int | str]]
    region: str
    status: str
    min_price: int
    metric: Literal["sum_units", "count", "max_price"]

    def matching(self) -> list[dict]:
        return [
            r for r in self.rows
            if r["region"] == self.region and r["status"] == self.status
            and r["price"] >= self.min_price
        ]

    @property
    def answer(self) -> str:
        m = self.matching()
        if self.metric == "sum_units":
            return str(sum(r["units"] for r in m))
        if self.metric == "count":
            return str(len(m))
        return str(max(r["price"] for r in m))


class DataReadback(_Model):
    region: str
    status: str
    min_price: int
    metric: Literal["sum_units", "count", "max_price"]
    answer: str


def sample_data(rng: random.Random, difficulty: int) -> DataSpec:
    n_rows = 15 + 12 * difficulty
    rows = [
        {
            "id": f"O{1000 + i}",
            "region": rng.choice(_data._REGIONS),
            "status": rng.choice(_data._STATUSES),
            "units": rng.randint(1, 40),
            "price": rng.randint(5, 400),
        }
        for i in range(n_rows)
    ]
    region, status = rng.choice(_data._REGIONS), rng.choice(_data._STATUSES)
    min_price = rng.choice([20, 50, 100, 150])

    def ok(r):
        return r["region"] == region and r["status"] == status and r["price"] >= min_price

    while sum(map(ok, rows)) < 2:
        row = rng.choice(rows)
        row["region"], row["status"] = region, status
        row["price"] = max(row["price"], min_price)
    return DataSpec(
        rows=rows, region=region, status=status, min_price=min_price,
        metric=rng.choice(["sum_units", "count", "max_price"]),
    )


def _check_data(spec: DataSpec, rb: DataReadback) -> list[str]:
    errs = []
    for f in ("region", "status", "min_price", "metric"):
        if getattr(rb, f) != getattr(spec, f):
            errs.append(f"{f}: {getattr(rb, f)!r} != {getattr(spec, f)!r}")
    if rb.answer != spec.answer:
        errs.append(f"answer {rb.answer!r} != {spec.answer!r}")
    return errs


# --- dispatch -----------------------------------------------------------------

Spec = Union[NluSpec, LogicSpec, DataSpec]
Readback = Union[NluReadback, LogicReadback, DataReadback]

SAMPLERS = {"nlu": sample_nlu, "logic": sample_logic, "data": sample_data}
READBACK_TYPES = {"nlu": NluReadback, "logic": LogicReadback, "data": DataReadback}
ANSWER_FORMATS = {
    "nlu": "node name (single word)",
    "logic": "first name (single word)",
    "data": "integer",
}
_CHECKS = {"nlu": _check_nlu, "logic": _check_logic, "data": _check_data}


def sample_spec(family: str, rng: random.Random, difficulty: int) -> Spec:
    return SAMPLERS[family](rng, max(0, min(difficulty, 3)))


def check_readback(spec: Spec, readback: Readback) -> list[str]:
    """Empty list means the reader recovered exactly the hidden structure."""
    return _CHECKS[spec.family](spec, readback)
