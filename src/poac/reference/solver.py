"""Reference solver: a deterministic oracle for every challenge family.

Purpose (evaluation only, never deployed with the verifier):

1. integration tests exercise the full protocol with a always-correct client;
2. the benchmark harness uses it to measure protocol overhead separate from
   model latency;
3. its existence *demonstrates* threat-model limitation L2: a source-aware
   deterministic script can solve template-generated challenges. The gate
   report must carry this finding to Phase 2 (private rotated corpus).
"""

from __future__ import annotations

import re
from itertools import permutations

from poac.protocol.models import (
    CodeChallenge,
    DataChallenge,
    DiagramChallenge,
    LogicChallenge,
    NluChallenge,
    ProofChallenge,
)


def solve(payload) -> str:
    if isinstance(payload, NluChallenge):
        return _solve_nlu(payload)
    if isinstance(payload, CodeChallenge):
        return _solve_code(payload)
    if isinstance(payload, LogicChallenge):
        return _solve_logic(payload)
    if isinstance(payload, DataChallenge):
        return _solve_data(payload)
    if isinstance(payload, DiagramChallenge):
        return _solve_diagram(payload)
    if isinstance(payload, ProofChallenge):
        return _solve_proof(payload)
    raise TypeError(f"unsupported payload: {type(payload)!r}")


def _solve_proof(c: ProofChallenge) -> str:
    """Template-recognition prover for the generated proposition grammar."""
    induction = (
        "by\n  intro n\n  induction n with\n"
        "  | zero => rfl\n  | succ k ih => simp only [{defs}]; omega"
    )
    if "poacG" in c.preamble:
        return induction.format(defs="poacF, poacG")
    if "poacF" in c.preamble:
        return induction.format(defs="poacF")
    if c.proposition.lstrip().startswith("∀"):
        return "by intro n; omega"
    return "by decide"


def _solve_nlu(c: NluChallenge) -> str:
    cutoff = int(re.search(r"before day (\d+)", c.question).group(1))
    days: dict[str, int] = {}
    for m in re.finditer(
        r"(?:the change log, (\w+) received the firmware patch on day (\d+)"
        r"|patch landing on (\w+) on day (\d+)"
        r"|recorded that (\w+) was patched on day (\d+))",
        c.narrative,
    ):
        days[m.group(1) or m.group(3) or m.group(5)] = int(
            m.group(2) or m.group(4) or m.group(6)
        )
    mismatch = {
        (m.group(1) or m.group(2))
        for m in re.finditer(
            r"(?:validation, (\w+) reported a checksum mismatch"
            r"|checksum mismatch for (\w+))",
            c.narrative,
        )
    }
    (answer,) = [n for n, d in days.items() if d < cutoff and n in mismatch]
    return answer


def trace_generated_program(source: str) -> int:
    """Interpreter for the narrow generated grammar (no dynamic execution)."""
    lines = source.splitlines()
    env: dict[str, int] = {}
    i = 0
    result: int | None = None
    while i < len(lines):
        line = lines[i]
        if m := re.fullmatch(r"(\w+) = (\d+)", line):
            env[m.group(1)] = int(m.group(2))
            i += 1
        elif m := re.fullmatch(r"for i in range\((\d+), (\d+)(?:, (\d+))?\):", line):
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
        elif m := re.fullmatch(r"if (\w+) > (\d+):", line):
            var, pivot = m.group(1), int(m.group(2))
            hi = re.fullmatch(r"(\w+) -= (\d+)", lines[i + 1].strip())
            lo = re.fullmatch(r"(\w+) \+= (\d+)", lines[i + 3].strip())
            if env[var] > pivot:
                env[var] -= int(hi.group(2))
            else:
                env[var] += int(lo.group(2))
            i += 4
        elif m := re.fullmatch(r"(\w+) \+= len\('(\w+)' \* (\d+)\)", line):
            env[m.group(1)] += len(m.group(2)) * int(m.group(3))
            i += 1
        elif m := re.fullmatch(r"print\((\w+)\)", line):
            result = env[m.group(1)]
            i += 1
        else:
            raise ValueError(f"unrecognized generated line: {line!r}")
    assert result is not None
    return result


def _solve_code(c: CodeChallenge) -> str:
    return str(trace_generated_program(c.source))


def _solve_logic(c: LogicChallenge) -> str:
    stmt = c.statement
    names_str = re.search(r"through \d+ \(rightmost\): ([^.]+)\.", stmt).group(1)
    names = [n.strip() for n in names_str.split(",")]
    k = len(names)
    pos_q = int(re.search(r"position (\d+)\?", c.question).group(1)) - 1

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

    (solution,) = [p for p in permutations(names) if all(f(p) for f in constraints)]
    return solution[pos_q]


def _solve_data(c: DataChallenge) -> str:
    instr = c.instruction
    region = re.search(r"in the (\w+) region", instr).group(1)
    status = re.search(r"status '(\w+)'", instr).group(1)
    min_price = int(re.search(r"price of at least (\d+)", instr).group(1))
    matching = [
        r
        for r in c.rows
        if r["region"] == region and r["status"] == status and r["price"] >= min_price
    ]
    if "total number of units" in instr:
        return str(sum(r["units"] for r in matching))
    if "the number of" in instr:
        return str(len(matching))
    return str(max(r["price"] for r in matching))


def _solve_diagram(c: DiagramChallenge) -> str:
    src, dst = re.search(r"from node (\w) to node (\w)", c.question).groups()
    svg = c.svg

    nodes: dict[str, tuple[float, float]] = {}
    for m in re.finditer(
        r'<circle cx="(-?\d+)" cy="(-?\d+)" r="16"[^/]*/>'
        r'<text x="(-?\d+)" y="(-?\d+)"[^>]*>(\w)</text>',
        svg,
    ):
        nodes[m.group(5)] = (float(m.group(1)), float(m.group(2)))

    weights: list[tuple[float, float, int]] = []
    for m in re.finditer(
        r'<text x="(-?\d+)" y="(-?\d+)" font-size="14" fill="crimson"[^>]*>(\d)</text>',
        svg,
    ):
        weights.append((float(m.group(1)), float(m.group(2)), int(m.group(3))))

    def nearest_node(x: float, y: float) -> str:
        return min(nodes, key=lambda n: (nodes[n][0] - x) ** 2 + (nodes[n][1] - y) ** 2)

    adj: dict[str, list[tuple[str, int]]] = {}
    for m in re.finditer(
        r'<line x1="(-?\d+)" y1="(-?\d+)" x2="(-?\d+)" y2="(-?\d+)"', svg
    ):
        x1, y1, x2, y2 = (float(g) for g in m.groups())
        a, b = nearest_node(x1, y1), nearest_node(x2, y2)
        # weight labels sit 30% along the edge from the (x1, y1) endpoint
        lx, ly = x1 + 0.3 * (x2 - x1), y1 + 0.3 * (y2 - y1)
        w = min(weights, key=lambda t: (t[0] - lx) ** 2 + (t[1] - ly) ** 2)[2]
        adj.setdefault(a, []).append((b, w))
        adj.setdefault(b, []).append((a, w))

    import heapq
    import math

    dist = {src: 0}
    heap = [(0, src)]
    while heap:
        d, u = heapq.heappop(heap)
        if u == dst:
            return str(d)
        if d > dist.get(u, math.inf):
            continue
        for v, w in adj.get(u, []):
            nd = d + w
            if nd < dist.get(v, math.inf):
                dist[v] = nd
                heapq.heappush(heap, (nd, v))
    raise ValueError("no path found in parsed SVG graph")
