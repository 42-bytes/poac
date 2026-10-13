"""Property tests for the five deterministic challenge families."""

import random
import re
from itertools import permutations

import pytest

from poac.challenges import make_challenge, normalize_answer
from poac.challenges.base import answers_match
from poac.challenges.diagram import dijkstra
from poac.challenges.registry import GENERATORS

FAMILIES = sorted(GENERATORS)
SEEDS = [bytes([i]) * 32 for i in range(8)]


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("difficulty", [0, 1, 2, 3])
def test_generation_is_deterministic(family, difficulty):
    seed = b"\x07" * 32
    a = make_challenge(family, seed, difficulty)
    b = make_challenge(family, seed, difficulty)
    assert a.payload == b.payload
    assert a.answer == b.answer


@pytest.mark.parametrize("family", FAMILIES)
def test_different_seeds_differ(family):
    payloads = {
        make_challenge(family, seed, 1).payload.model_dump_json() for seed in SEEDS
    }
    assert len(payloads) > 1, "seeds must vary the instance"


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("seed", SEEDS)
def test_answers_are_bounded_strings(family, seed):
    gc = make_challenge(family, seed, 2)
    # proof answers are whole tactic blocks; the rest are short values
    limit = 2_000 if family == "proof" else 40
    assert isinstance(gc.answer, str) and 0 < len(gc.answer) <= limit
    if family != "proof":
        assert answers_match(gc.answer.upper() + "  ", gc.answer)


def test_unknown_family_rejected():
    with pytest.raises(KeyError):
        make_challenge("haiku", b"\x00" * 32, 1)


# --- family-specific independent re-verification ---------------------------


@pytest.mark.parametrize("seed", SEEDS)
def test_nlu_exactly_one_candidate_satisfies_constraints(seed):
    gc = make_challenge("nlu", seed, 2)
    text = gc.payload.narrative
    cutoff = int(re.search(r"before day (\d+)", gc.payload.question).group(1))

    # reconstruct patch-day facts from the narrative itself
    days: dict[str, int] = {}
    for m in re.finditer(
        r"(?:the change log, (\w+) received the firmware patch on day (\d+)"
        r"|patch landing on (\w+) on day (\d+)"
        r"|recorded that (\w+) was patched on day (\d+))",
        text,
    ):
        node = m.group(1) or m.group(3) or m.group(5)
        days[node] = int(m.group(2) or m.group(4) or m.group(6))

    mismatch = {
        (m.group(1) or m.group(2))
        for m in re.finditer(
            r"(?:validation, (\w+) reported a checksum mismatch"
            r"|checksum mismatch for (\w+))",
            text,
        )
    }
    satisfying = [n for n, d in days.items() if d < cutoff and n in mismatch]
    assert satisfying == [gc.answer]


def _trace_generated_program(source: str) -> int:
    """Independent interpreter for the narrow generated grammar (no eval)."""
    lines = source.splitlines()
    env: dict[str, int] = {}
    i = 0
    result: int | None = None
    while i < len(lines):
        line = lines[i]
        m = re.fullmatch(r"(\w+) = (\d+)", line)
        if m:
            env[m.group(1)] = int(m.group(2))
            i += 1
            continue
        m = re.fullmatch(r"for i in range\((\d+), (\d+)(?:, (\d+))?\):", line)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            step = int(m.group(3)) if m.group(3) else 1
            body = lines[i + 1].strip()
            badd = re.fullmatch(r"(\w+) \+= i \* (\d+)", body)
            bmod = re.fullmatch(r"(\w+) = \((\w+) \* i\) % (\d+)", body)
            for it in range(a, b, step):
                if badd:
                    env[badd.group(1)] += it * int(badd.group(2))
                else:
                    env[bmod.group(1)] = (env[bmod.group(2)] * it) % int(bmod.group(3))
            i += 2
            continue
        m = re.fullmatch(r"if (\w+) > (\d+):", line)
        if m:
            var, pivot = m.group(1), int(m.group(2))
            hi = re.fullmatch(r"(\w+) -= (\d+)", lines[i + 1].strip())
            lo = re.fullmatch(r"(\w+) \+= (\d+)", lines[i + 3].strip())
            if env[var] > pivot:
                env[var] -= int(hi.group(2))
            else:
                env[var] += int(lo.group(2))
            i += 4
            continue
        m = re.fullmatch(r"(\w+) \+= len\('(\w+)' \* (\d+)\)", line)
        if m:
            env[m.group(1)] += len(m.group(2)) * int(m.group(3))
            i += 1
            continue
        m = re.fullmatch(r"print\((\w+)\)", line)
        if m:
            result = env[m.group(1)]
            i += 1
            continue
        raise AssertionError(f"unrecognized generated line: {line!r}")
    assert result is not None
    return result


@pytest.mark.parametrize("seed", SEEDS)
def test_code_answer_matches_independent_trace(seed):
    gc = make_challenge("code", seed, 2)
    assert str(_trace_generated_program(gc.payload.source)) == gc.answer


@pytest.mark.parametrize("seed", SEEDS)
def test_logic_solution_is_unique_and_correct(seed):
    gc = make_challenge("logic", seed, 2)
    stmt, question = gc.payload.statement, gc.payload.question
    names_str = re.search(r"through \d+ \(rightmost\): ([^.]+)\.", stmt).group(1)
    names = [n.strip() for n in names_str.split(",")]
    k = len(names)
    pos_q = int(re.search(r"position (\d+)\?", question).group(1)) - 1

    constraints = []
    for m in re.finditer(r"(\w+) is somewhere to the left of (\w+)\.", stmt):
        a, b = m.groups()
        constraints.append(lambda p, a=a, b=b: p.index(a) < p.index(b))
    for m in re.finditer(r"(\w+) stands immediately to the left of (\w+)\.", stmt):
        a, b = m.groups()
        constraints.append(lambda p, a=a, b=b: p.index(a) + 1 == p.index(b))
    for m in re.finditer(r"(\w+) is not standing next to (\w+)\.", stmt):
        a, b = m.groups()
        constraints.append(lambda p, a=a, b=b: abs(p.index(a) - p.index(b)) != 1)
    for m in re.finditer(r"(\w+) is not in position (\d+)\.", stmt):
        a, i = m.group(1), int(m.group(2)) - 1
        constraints.append(lambda p, a=a, i=i: p.index(a) != i)
    for m in re.finditer(r"(\w+) stands at one end of the line\.", stmt):
        a = m.group(1)
        constraints.append(lambda p, a=a, k=k: p.index(a) in (0, k - 1))

    solutions = [p for p in permutations(names) if all(c(p) for c in constraints)]
    assert len(solutions) == 1
    assert solutions[0][pos_q] == gc.answer


@pytest.mark.parametrize("seed", SEEDS)
def test_data_answer_matches_recomputation(seed):
    gc = make_challenge("data", seed, 2)
    instr = gc.payload.instruction
    region = re.search(r"in the (\w+) region", instr).group(1)
    status = re.search(r"status '(\w+)'", instr).group(1)
    min_price = int(re.search(r"price of at least (\d+)", instr).group(1))
    matching = [
        r
        for r in gc.payload.rows
        if r["region"] == region and r["status"] == status and r["price"] >= min_price
    ]
    assert matching, "instruction must match at least one row"
    if "total number of units" in instr:
        expected = sum(r["units"] for r in matching)
    elif "the number of" in instr:
        expected = len(matching)
    else:
        expected = max(r["price"] for r in matching)
    assert str(expected) == gc.answer


@pytest.mark.parametrize("seed", SEEDS)
def test_diagram_shortest_path_verified_by_enumeration(seed):
    gc = make_challenge("diagram", seed, 1)
    svg, q = gc.payload.svg, gc.payload.question
    src, dst = re.search(r"from node (\w) to node (\w)", q).groups()

    # rebuild the graph with the same seed (mirroring the generator's
    # ambiguity-rejection loop) to check SVG consistency
    from poac.challenges.diagram import (  # test-only imports
        _build_graph,
        _labels_unambiguous,
        _node_positions,
    )

    rng = random.Random(int.from_bytes(seed, "big"))
    n = min(5 + 1, 9)
    pos = _node_positions([chr(ord("A") + i) for i in range(n)])
    for _ in range(60):
        edges = _build_graph(rng, n)
        if _labels_unambiguous(edges, pos):
            break

    for w in edges.values():
        assert f">{w}</text>" in svg

    # exhaustive simple-path enumeration independently checks dijkstra
    adj: dict[str, list[tuple[str, int]]] = {}
    for (a, b), w in edges.items():
        adj.setdefault(a, []).append((b, w))
        adj.setdefault(b, []).append((a, w))

    best = [float("inf")]

    def walk(node, cost, seen):
        if cost >= best[0]:
            return
        if node == dst:
            best[0] = cost
            return
        for nxt, w in adj.get(node, []):
            if nxt not in seen:
                walk(nxt, cost + w, seen | {nxt})

    walk(src, 0, frozenset({src}))
    assert str(best[0]) == gc.answer
    assert best[0] == dijkstra(edges, src, dst)


def test_normalize_answer():
    assert normalize_answer("  Foo   BAR ") == "foo bar"


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("difficulty", [0, 1, 2, 3])
def test_reference_solver_is_a_true_oracle(family, difficulty):
    """The payload alone must fully determine the answer at every difficulty.

    Catches ambiguity bugs like weight labels stacking near the circle
    center in dense diagrams (found by this sweep at difficulty 3).
    """
    from poac.reference.solver import solve

    for i in range(150):
        seed = i.to_bytes(4, "big") + b"oracle-sweep".ljust(28, b"_")
        gc = make_challenge(family, seed, difficulty)
        assert answers_match(solve(gc.payload), gc.answer), (
            f"{family} d{difficulty} seed{i}: payload is ambiguous or solver wrong"
        )
