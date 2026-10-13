"""Small statistics helpers for the evaluation harness."""

from __future__ import annotations

import math


def wilson_ci(successes: int, trials: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a binomial proportion.

    Used so that "0 passes in N attempts" is reported as an upper bound on
    the true pass probability, never as proof of impossibility.
    """
    if trials == 0:
        return (0.0, 1.0)
    p = successes / trials
    denom = 1 + z**2 / trials
    center = (p + z**2 / (2 * trials)) / denom
    margin = (z / denom) * math.sqrt(p * (1 - p) / trials + z**2 / (4 * trials**2))
    return (max(0.0, center - margin), min(1.0, center + margin))


def percentiles(values: list[float], points=(50, 95, 99)) -> dict[str, float]:
    if not values:
        return {f"p{p}": float("nan") for p in points}
    ordered = sorted(values)
    out = {}
    for p in points:
        idx = min(len(ordered) - 1, max(0, round(p / 100 * (len(ordered) - 1))))
        out[f"p{p}"] = ordered[idx]
    return out
