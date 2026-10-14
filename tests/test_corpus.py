"""Private corpus (phase 2, task B1).

What must hold:
* answers are code-derived from the spec, never from the author;
* an author whose prose does not read back to the spec is rejected;
* an author that copies the public template is rejected (solver can solve it);
* stored instances are NOT solvable by the public-template reference solver
  but ARE accepted by the orchestrator with the stored answer;
* exposure accounting: least-exposed first, retirement, batch rotation,
  template fallback when a bucket is empty (counted).
"""

from __future__ import annotations

import random
from itertools import permutations

import pytest

from poac.challenges import make_challenge
from poac.corpus import CorpusSource, CorpusStore
from poac.corpus.author import (
    DataRendering,
    LogicRendering,
    NluRendering,
    StubAuthor,
    payload_from_rendering,
)
from poac.corpus.build import author_instance, build
from poac.corpus.specs import (
    CORPUS_FAMILIES,
    LogicSpec,
    NluSpec,
    check_readback,
    sample_spec,
)
from poac.credentials.issuer import ReceiptIssuer
from poac.protocol.models import CapabilityTier, NextRoundResponse, SessionPassedResponse
from poac.reference.solver import solve
from poac.sessions.orchestrator import Orchestrator


@pytest.fixture
def store(tmp_path):
    return CorpusStore(str(tmp_path / "corpus.sqlite"), max_exposures=3)


def _solver_fails(payload, answer) -> bool:
    try:
        return solve(payload).strip().lower() != answer.lower()
    except Exception:
        return True


# --- specs --------------------------------------------------------------------


@pytest.mark.parametrize("family", CORPUS_FAMILIES)
@pytest.mark.parametrize("difficulty", [0, 3])
def test_specs_have_unique_code_derived_answers(family, difficulty):
    for i in range(20):
        spec = sample_spec(family, random.Random(i), difficulty)
        assert spec.answer
        if isinstance(spec, LogicSpec):
            assert spec.unique_solution()
            assert spec.answer == spec.order[spec.query_position - 1]
        if isinstance(spec, NluSpec):
            hits = [n for n in spec.nodes if n.day < spec.cutoff and n.checksum == "mismatch"]
            assert len(hits) == 1 and spec.red_herring != spec.answer


def test_logic_spec_detects_underconstrained_readback():
    spec = sample_spec("logic", random.Random(1), 2)
    rb_type = type(StubAuthor().readback(payload_from_rendering(spec, StubAuthor().render(spec, 0))))
    rb = rb_type(names=spec.names, constraints=spec.constraints[:-1],
                 query_position=spec.query_position, answer=spec.answer)
    errs = check_readback(spec, rb)
    assert errs and "constraints missing" in errs[0]


# --- authoring gates ----------------------------------------------------------


@pytest.mark.parametrize("family", CORPUS_FAMILIES)
def test_stub_author_passes_all_gates(family):
    inst, reason = author_instance(StubAuthor(), family, 2, random.Random(7), "t")
    assert inst is not None, reason
    assert _solver_fails(inst.payload, inst.answer), "stub surface form is template-like"


class _LyingAuthor(StubAuthor):
    """Prose is fine, but the reader disagrees on one fact → must be rejected."""

    name = "liar"

    def readback(self, payload):
        rb = super().readback(payload)
        if hasattr(rb, "cutoff"):
            return rb.model_copy(update={"cutoff": rb.cutoff + 1})
        if hasattr(rb, "query_position"):
            return rb.model_copy(update={"answer": "Nobody"})
        return rb.model_copy(update={"min_price": rb.min_price + 1})


@pytest.mark.parametrize("family", CORPUS_FAMILIES)
def test_readback_mismatch_is_rejected(family, store):
    rep = build(store, _LyingAuthor(), family, 1, 3, seed=1)
    assert rep.accepted == 0 and len(rep.rejected) == 9
    assert all(r.startswith("readback mismatch") for r in rep.rejected)
    assert store.stats().active == 0


class _TemplateCopyingAuthor(StubAuthor):
    """Returns the public template text verbatim → solver can solve → rejected."""

    name = "copycat"

    def render(self, spec, style_seed):
        gc = _template_equivalent(spec)
        p = gc.payload
        if spec.family == "nlu":
            return NluRendering(narrative=p.narrative, question=p.question)
        if spec.family == "logic":
            return LogicRendering(statement=p.statement, question=p.question)
        return DataRendering(instruction=p.instruction)

    def readback(self, payload):
        # perfect reader (uses the solver) so only the privacy gate can fail
        from poac.corpus.specs import DataReadback, LogicReadback, NluReadback
        import re

        if payload.family == "data":
            i = payload.instruction
            metric = ("sum_units" if "total number of units" in i
                      else "count" if "the number of" in i else "max_price")
            return DataReadback(
                region=re.search(r"in the (\w+) region", i)[1],
                status=re.search(r"status '(\w+)'", i)[1],
                min_price=int(re.search(r"at least (\d+)", i)[1]),
                metric=metric, answer=solve(payload),
            )
        raise NotImplementedError


def _template_equivalent(spec):
    """Build a template payload that encodes the same filter as the spec."""
    from poac.protocol.models import DataChallenge

    metric_text = {"sum_units": "the total number of units across",
                   "count": "the number of", "max_price": "the highest price among"}
    instr = (
        f"Compute {metric_text[spec.metric]} orders in the {spec.region} region with status "
        f"'{spec.status}' and a price of at least {spec.min_price}. Ignore all other "
        "orders. Answer with the integer only."
    )
    from poac.challenges.base import GeneratedChallenge

    return GeneratedChallenge(
        payload=DataChallenge(family="data", rows=spec.rows, instruction=instr),
        answer=spec.answer, answer_format="integer",
    )


def test_template_copy_is_rejected_by_privacy_gate(store):
    rep = build(store, _TemplateCopyingAuthor(), "data", 1, 2, seed=3)
    assert rep.accepted == 0
    assert all("reference solver" in r for r in rep.rejected), rep.rejected


def test_build_stores_requested_count_and_answers_are_spec_derived(store):
    rep = build(store, StubAuthor(), "nlu", 2, 5, batch="b1", seed=11)
    assert rep.accepted == 5 and not rep.rejected
    for inst in store.all_active():
        # recompute from the stub's own readback: the stored answer is the
        # code-derived one, independent of what any author says
        rb = StubAuthor().readback(inst.payload)
        assert inst.answer == rb.answer
        assert inst.batch == "b1" and inst.author == "stub"
        assert _solver_fails(inst.payload, inst.answer)


# --- store --------------------------------------------------------------------


def test_draw_prefers_least_exposed_then_retires(store):
    build(store, StubAuthor(), "data", 0, 2, seed=5)
    rng = random.Random(0)
    seen = [store.draw("data", 0, rng).payload.instruction for _ in range(2)]
    assert len(set(seen)) == 2, "second draw must pick the unexposed instance"
    for _ in range(4):
        store.draw("data", 0, rng)
    s = store.stats()
    assert s.exposures == 6 and s.active == 0 and s.retired == 2  # max_exposures=3
    assert store.draw("data", 0, rng) is None


def test_retire_batch_rotates_out_old_instances(store):
    build(store, StubAuthor(), "logic", 1, 3, batch="old", seed=1)
    build(store, StubAuthor(), "logic", 1, 2, batch="new", seed=2)
    assert store.retire_batch("old") == 3
    assert store.stats().by_family == {("logic", 1): 2}
    assert all(i.batch == "new" for i in store.all_active())


def test_instances_survive_reopen(tmp_path):
    path = str(tmp_path / "c.sqlite")
    build(CorpusStore(path), StubAuthor(), "nlu", 0, 2, seed=9)
    assert CorpusStore(path).stats().active == 2


# --- source + orchestrator ----------------------------------------------------


def test_source_serves_corpus_and_falls_back_with_count(store):
    build(store, StubAuthor(), "logic", 2, 1, seed=4)
    src = CorpusSource(store)
    seed = b"\x01" * 32
    gc = src.draw("logic", seed, 2)
    assert _solver_fails(gc.payload, gc.answer) and src.served == 1
    # bucket now empty for d2 (max_exposures=3 → still 2 draws left); drain
    src.draw("logic", seed, 2), src.draw("logic", seed, 2)
    tmpl = src.draw("logic", seed, 2)
    assert tmpl == make_challenge("logic", seed, 2)
    assert src.fallbacks == {("logic", 2): 1}
    # families without a corpus always come from templates, uncounted
    assert src.draw("proof", seed, 3) == make_challenge("proof", seed, 3)
    assert src.fallbacks == {("logic", 2): 1}


class _Recording:
    def __init__(self, inner):
        self.inner, self.last = inner, None

    def draw(self, family, seed, difficulty):
        self.last = self.inner.draw(family, seed, difficulty)
        return self.last


def test_full_session_from_corpus_passes_with_stored_answers(store):
    for fam in CORPUS_FAMILIES:
        build(store, StubAuthor(), fam, 2, 4, seed=fam.__hash__() & 0xFFFF)
    src = _Recording(CorpusSource(store))
    t = [1000.0]
    orch = Orchestrator(ReceiptIssuer.generate(), server_secret=b"k" * 32,
                        clock=lambda: t[0], source=src)
    created = orch.create_session(CapabilityTier.C2, None)
    rnd, outcome, corpus_rounds = created.round, None, 0
    while True:
        t[0] += 1.0
        if rnd.challenge.family in CORPUS_FAMILIES:
            assert _solver_fails(rnd.challenge, src.last.answer)
            corpus_rounds += 1
        outcome = orch.submit(created.session_id, rnd.round_index, rnd.nonce, src.last.answer)
        if isinstance(outcome, NextRoundResponse):
            rnd = outcome.round
        else:
            break
    assert isinstance(outcome, SessionPassedResponse), outcome
    assert corpus_rounds >= 1 and src.inner.fallbacks == {}
