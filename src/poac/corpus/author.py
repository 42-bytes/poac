"""Authors turn specs into prose and read prose back into specs.

Two implementations:

* ``StubAuthor`` — deterministic, offline. Produces a non-template surface
  form (so the public reference solver fails on it) and reads it back
  exactly. Used by the test suite and for dry runs of the pipeline.
* ``PydanticAIAuthor`` — LLM-backed via Pydantic AI with structured output
  (Pydantic models) for both directions. Render and read-back may use
  different models; using different vendors is recommended so a shared
  blind spot cannot pass a wrong narrative.

Neither author ever produces the answer that is stored. The answer comes
from the spec (``poac.corpus.specs``); the author's read-back answer is only
a consistency check.
"""

from __future__ import annotations

import random
from typing import Literal, Protocol, Union

from pydantic import BaseModel, ConfigDict

from poac.challenges.base import ChallengePayload
from poac.corpus.specs import (
    READBACK_TYPES,
    Constraint,
    DataReadback,
    DataSpec,
    LogicReadback,
    LogicSpec,
    NluReadback,
    NluSpec,
    NodeFact,
    Readback,
    Spec,
)
from poac.protocol.models import DataChallenge, LogicChallenge, NluChallenge


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NluRendering(_Model):
    narrative: str
    question: str


class LogicRendering(_Model):
    statement: str
    question: str


class DataRendering(_Model):
    instruction: str


Rendering = Union[NluRendering, LogicRendering, DataRendering]
RENDERING_TYPES = {"nlu": NluRendering, "logic": LogicRendering, "data": DataRendering}


def payload_from_rendering(spec: Spec, rendering: Rendering) -> ChallengePayload:
    if spec.family == "nlu":
        return NluChallenge(family="nlu", narrative=rendering.narrative, question=rendering.question)
    if spec.family == "logic":
        return LogicChallenge(family="logic", statement=rendering.statement, question=rendering.question)
    return DataChallenge(family="data", rows=spec.rows, instruction=rendering.instruction)


class Author(Protocol):
    name: str

    def render(self, spec: Spec, style_seed: int) -> Rendering: ...

    def readback(self, payload: ChallengePayload) -> Readback: ...


# --- offline stub -------------------------------------------------------------

_STUB_FILLER = [
    "Unrelated: the coffee machine on floor 3 was also replaced that week.",
    "Side note: the audit intern asked for read access to the tracker twice.",
    "Context: the quarterly review has been moved to the following Tuesday.",
]
_KIND_PHRASES = {
    "left_of": "{a} precedes {b}",
    "immediately_left": "{a} is directly before {b}",
    "not_adjacent": "{a} and {b} are separated",
    "not_at": "{a} avoids slot {position}",
    "at_edge": "{a} occupies an end slot",
}


class StubAuthor:
    """Deterministic paraphraser with a tabular, non-template surface form."""

    name = "stub"

    def render(self, spec: Spec, style_seed: int) -> Rendering:
        rng = random.Random(style_seed)
        if isinstance(spec, NluSpec):
            lines = [
                f"[{n.name}] patched: d{n.day}; integrity={n.checksum}; "
                f"site={n.site}; owner={n.engineer}"
                for n in spec.nodes
            ] + [rng.choice(_STUB_FILLER) for _ in range(spec.n_filler)]
            rng.shuffle(lines)
            narrative = (
                f"Review notes. First guess pointed at {spec.red_herring}; disregard. "
                + " ".join(lines)
            )
            question = (
                f"Exactly one node has a patch day lower than {spec.cutoff} and "
                "integrity=mismatch. Name it (node name only)."
            )
            return NluRendering(narrative=narrative, question=question)
        if isinstance(spec, LogicSpec):
            rules = [
                _KIND_PHRASES[c.kind].format(a=c.a, b=c.b, position=c.position) + "."
                for c in spec.constraints
            ]
            statement = (
                f"Slots 1..{len(spec.names)} are filled left to right by "
                f"{', '.join(spec.names)}. Rules: " + " ".join(rules)
            )
            question = f"Name the occupant of slot {spec.query_position} (name only)."
            return LogicRendering(statement=statement, question=question)
        assert isinstance(spec, DataSpec)
        metric_txt = {"sum_units": "sum of units", "count": "row count", "max_price": "max price"}
        return DataRendering(
            instruction=(
                f"Filter rows where region={spec.region}, status={spec.status}, "
                f"price>={spec.min_price}. Report the {metric_txt[spec.metric]} "
                "as a bare integer."
            )
        )

    def readback(self, payload: ChallengePayload) -> Readback:
        import re

        if isinstance(payload, NluChallenge):
            facts = [
                NodeFact(name=m[0], day=int(m[1]), checksum=m[2], site=m[3], engineer=m[4])
                for m in re.findall(
                    r"\[(\w+)\] patched: d(\d+); integrity=(\w+); site=(\w+); owner=(\w+)",
                    payload.narrative,
                )
            ]
            cutoff = int(re.search(r"lower than (\d+)", payload.question).group(1))
            (ans,) = [f.name for f in facts if f.day < cutoff and f.checksum == "mismatch"]
            return NluReadback(facts=facts, cutoff=cutoff, answer=ans)
        if isinstance(payload, LogicChallenge):
            s = payload.statement
            names = re.search(r"left to right by ([^.]+)\. Rules:", s).group(1).split(", ")
            cons: list[Constraint] = []
            for a, b in re.findall(r"(\w+) precedes (\w+)\.", s):
                cons.append(Constraint(kind="left_of", a=a, b=b))
            for a, b in re.findall(r"(\w+) is directly before (\w+)\.", s):
                cons.append(Constraint(kind="immediately_left", a=a, b=b))
            for a, b in re.findall(r"(\w+) and (\w+) are separated\.", s):
                cons.append(Constraint(kind="not_adjacent", a=a, b=b))
            for a, p in re.findall(r"(\w+) avoids slot (\d+)\.", s):
                cons.append(Constraint(kind="not_at", a=a, position=int(p)))
            for a in re.findall(r"(\w+) occupies an end slot\.", s):
                cons.append(Constraint(kind="at_edge", a=a))
            q = int(re.search(r"slot (\d+)", payload.question).group(1))
            from itertools import permutations

            (sol,) = [p for p in permutations(names) if all(c.holds(p) for c in cons)]
            return LogicReadback(names=names, constraints=cons, query_position=q, answer=sol[q - 1])
        assert isinstance(payload, DataChallenge)
        m = re.search(
            r"region=(\w+), status=(\w+), price>=(\d+)\. Report the (sum of units|row count|max price)",
            payload.instruction,
        )
        metric = {"sum of units": "sum_units", "row count": "count", "max price": "max_price"}[m[4]]
        spec = DataSpec(rows=payload.rows, region=m[1], status=m[2], min_price=int(m[3]), metric=metric)
        return DataReadback(
            region=m[1], status=m[2], min_price=int(m[3]), metric=metric, answer=spec.answer
        )


# --- LLM-backed ---------------------------------------------------------------

_THEMES = [
    "satellite ground-station maintenance", "hospital pharmacy inventory",
    "container-port crane scheduling", "university lab equipment audit",
    "municipal water-pump telemetry", "film-festival projector fleet",
    "wind-farm turbine controllers", "railway signalling cabinets",
]

_RENDER_INSTRUCTIONS = {
    "nlu": (
        "You write long-context reading-comprehension tasks for machines. You are "
        "given a JSON spec with candidate nodes and, per node, a patch day, an "
        "integrity checksum result (match/mismatch), a site and an engineer, plus "
        "a cutoff day, a red-herring node and a count of filler sentences.\n"
        "Write a narrative of 1-3 paragraphs in the style of the given theme that "
        "states EVERY fact for EVERY node exactly once, in varied phrasing, with "
        "facts for one node scattered across different sentences, the given number "
        "of plausible unrelated filler sentences, and an early misleading remark "
        "that the red-herring node was initially suspected. Use node names, site "
        "names, engineer names, days and checksum words verbatim; never invent "
        "additional nodes, days or checksum results; never state the answer.\n"
        "Then write a question asking for the single node patched strictly before "
        "the cutoff day AND with a checksum mismatch, ending with 'Answer with the "
        "node name only.'"
    ),
    "logic": (
        "You write ordering puzzles for machines. You are given a JSON spec with "
        "names, a hidden left-to-right order, a list of constraints and a "
        "1-based query position. Write a statement in the style of the given theme "
        "that introduces the names as occupying positions 1 (leftmost) to N "
        "(rightmost) and expresses EVERY constraint exactly once in natural, varied "
        "wording. Constraint kinds: left_of (a somewhere before b), "
        "immediately_left (a directly before b), not_adjacent (a and b not next to "
        "each other), not_at (a not in that position), at_edge (a at either end). "
        "Do not add, drop, weaken or strengthen constraints; do not reveal the "
        "order. Then write a question asking who is at the query position, ending "
        "with 'Answer with the name only.'"
    ),
    "data": (
        "You write data-aggregation instructions for machines. You are given a "
        "JSON spec with a filter (region, status, minimum price inclusive) and a "
        "metric (sum_units = total units of matching rows, count = number of "
        "matching rows, max_price = highest price among matching rows). Write a "
        "single instruction, in the style of the given theme, that unambiguously "
        "asks for that metric over rows matching ALL filter conditions, mentions "
        "at least one distractor condition the reader must ignore, and ends with "
        "'Answer with the integer only.' Use the exact region and status values."
    ),
}

_READBACK_INSTRUCTIONS = {
    "nlu": (
        "Extract from the narrative, for every node mentioned, its patch day, "
        "checksum result (match or mismatch), site and engineer. Extract the "
        "cutoff day from the question. Then answer the question. Be literal; do "
        "not infer facts that are not stated."
    ),
    "logic": (
        "Extract the list of names and every ordering constraint stated, using "
        "kinds left_of, immediately_left, not_adjacent, not_at (1-based position) "
        "or at_edge. Extract the queried 1-based position. Then solve the puzzle "
        "and answer with the name."
    ),
    "data": (
        "Extract the filter (region, status, minimum price) and metric "
        "(sum_units, count or max_price) the instruction asks for, ignoring any "
        "distractor conditions it tells you to ignore. Then compute the answer "
        "over the rows and return it as a string."
    ),
}


class PydanticAIAuthor:
    """LLM author with structured output. Needs the ``llm`` extra."""

    def __init__(self, render_model: str, readback_model: str | None = None):
        from pydantic_ai import Agent

        self.name = f"llm:{render_model}->{readback_model or render_model}"
        self._render = {
            fam: Agent(render_model, output_type=RENDERING_TYPES[fam], instructions=txt)
            for fam, txt in _RENDER_INSTRUCTIONS.items()
        }
        self._read = {
            fam: Agent(readback_model or render_model, output_type=READBACK_TYPES[fam],
                       instructions=txt)
            for fam, txt in _READBACK_INSTRUCTIONS.items()
        }

    def render(self, spec: Spec, style_seed: int) -> Rendering:
        theme = _THEMES[style_seed % len(_THEMES)]
        prompt = f"Theme: {theme}\nSpec:\n{spec.model_dump_json()}"
        return self._render[spec.family].run_sync(prompt).output

    def readback(self, payload: ChallengePayload) -> Readback:
        return self._read[payload.family].run_sync(payload.model_dump_json()).output
