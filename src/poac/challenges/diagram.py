"""Diagram family: shortest-path questions over a generated SVG graph.

A connected weighted graph is generated (random spanning tree plus extra
edges), rendered to SVG with labeled nodes and edge weights, and the client
is asked for the total weight of the cheapest path between two nodes. The
expected cost is computed with Dijkstra and independently re-checked by
exhaustive path enumeration in tests.
"""

from __future__ import annotations

import heapq
import math
import random
import string

from poac.challenges.base import GeneratedChallenge
from poac.protocol.models import DiagramChallenge


def _build_graph(rng: random.Random, n: int) -> dict[tuple[str, str], int]:
    labels = list(string.ascii_uppercase[:n])
    edges: dict[tuple[str, str], int] = {}

    def add(a: str, b: str) -> None:
        key = (min(a, b), max(a, b))
        if key not in edges and a != b:
            edges[key] = rng.randint(1, 9)

    shuffled = labels[:]
    rng.shuffle(shuffled)
    for i in range(1, n):  # spanning tree: connected by construction
        add(shuffled[i], shuffled[rng.randrange(i)])
    for _ in range(n // 2 + 1):  # extra edges create alternative paths
        add(rng.choice(labels), rng.choice(labels))
    return edges


def dijkstra(edges: dict[tuple[str, str], int], src: str, dst: str) -> int:
    adj: dict[str, list[tuple[str, int]]] = {}
    for (a, b), w in edges.items():
        adj.setdefault(a, []).append((b, w))
        adj.setdefault(b, []).append((a, w))
    dist = {src: 0}
    heap = [(0, src)]
    while heap:
        d, u = heapq.heappop(heap)
        if u == dst:
            return d
        if d > dist.get(u, math.inf):
            continue
        for v, w in adj.get(u, []):
            nd = d + w
            if nd < dist.get(v, math.inf):
                dist[v] = nd
                heapq.heappush(heap, (nd, v))
    raise ValueError("graph is not connected")


# Edge-weight labels sit 30% along the edge (from the alphabetically first
# node) instead of at the midpoint: with many nodes on a circle, all long
# chords pass near the center, which would stack the labels ambiguously.
LABEL_T = 0.3
MIN_LABEL_SEPARATION = 18.0
MIN_LABEL_NODE_DISTANCE = 22.0


def _node_positions(labels: list[str]) -> dict[str, tuple[float, float]]:
    n = len(labels)
    cx, cy, r = 250, 250, 200
    return {
        lab: (
            cx + r * math.cos(2 * math.pi * i / n - math.pi / 2),
            cy + r * math.sin(2 * math.pi * i / n - math.pi / 2),
        )
        for i, lab in enumerate(labels)
    }


def label_position(
    p1: tuple[float, float], p2: tuple[float, float]
) -> tuple[float, float]:
    return (p1[0] + LABEL_T * (p2[0] - p1[0]), p1[1] + LABEL_T * (p2[1] - p1[1]))


def _labels_unambiguous(
    edges: dict[tuple[str, str], int], pos: dict[str, tuple[float, float]]
) -> bool:
    """Generation-time ambiguity check: every weight label must be clearly
    separated from all other labels and from node circles."""
    points = [label_position(pos[a], pos[b]) for (a, b) in edges]
    for i, (x1, y1) in enumerate(points):
        for x2, y2 in points[i + 1 :]:
            if math.hypot(x1 - x2, y1 - y2) < MIN_LABEL_SEPARATION:
                return False
        for nx, ny in pos.values():
            if math.hypot(x1 - nx, y1 - ny) < MIN_LABEL_NODE_DISTANCE:
                return False
    return True


def _render_svg(edges: dict[tuple[str, str], int], labels: list[str]) -> str:
    pos = _node_positions(labels)
    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500" '
        'viewBox="0 0 500 500">'
    ]
    for (a, b), w in sorted(edges.items()):
        (x1, y1), (x2, y2) = pos[a], pos[b]
        lx, ly = label_position((x1, y1), (x2, y2))
        parts.append(
            f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" '
            'stroke="black" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{lx:.0f}" y="{ly:.0f}" font-size="14" fill="crimson" '
            f'text-anchor="middle">{w}</text>'
        )
    for lab, (x, y) in pos.items():
        parts.append(
            f'<circle cx="{x:.0f}" cy="{y:.0f}" r="16" fill="white" stroke="black"/>'
        )
        parts.append(
            f'<text x="{x:.0f}" y="{y + 5:.0f}" font-size="16" '
            f'text-anchor="middle">{lab}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def generate(rng: random.Random, difficulty: int) -> GeneratedChallenge:
    n = min(5 + difficulty, 9)
    labels = list(string.ascii_uppercase[:n])
    pos = _node_positions(labels)
    for _ in range(60):  # regenerate until the rendering is unambiguous
        edges = _build_graph(rng, n)
        if _labels_unambiguous(edges, pos):
            break
    else:  # pragma: no cover - separation is easily satisfiable
        raise RuntimeError("could not generate an unambiguous diagram")

    src, dst = rng.sample(labels, 2)
    cost = dijkstra(edges, src, dst)

    svg = _render_svg(edges, labels)
    question = (
        f"The SVG below shows an undirected weighted graph (edge weights in "
        f"red). What is the total weight of the cheapest path from node {src} "
        f"to node {dst}? Answer with the integer only."
    )
    return GeneratedChallenge(
        payload=DiagramChallenge(family="diagram", svg=svg, question=question),
        answer=str(cost),
        answer_format="integer",
    )
