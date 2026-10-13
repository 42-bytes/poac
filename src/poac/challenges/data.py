"""Structured-data synthesis family.

Generates a table of order records and a natural-language aggregation
instruction with distractor conditions. The expected answer is computed
directly from the generated rows.
"""

from __future__ import annotations

import random

from poac.challenges.base import GeneratedChallenge
from poac.protocol.models import DataChallenge

_REGIONS = ["north", "south", "east", "west"]
_STATUSES = ["shipped", "pending", "returned"]


def generate(rng: random.Random, difficulty: int) -> GeneratedChallenge:
    n_rows = 15 + 12 * difficulty
    rows = [
        {
            "id": f"O{1000 + i}",
            "region": rng.choice(_REGIONS),
            "status": rng.choice(_STATUSES),
            "units": rng.randint(1, 40),
            "price": rng.randint(5, 400),
        }
        for i in range(n_rows)
    ]

    region = rng.choice(_REGIONS)
    status = rng.choice(_STATUSES)
    min_price = rng.choice([20, 50, 100, 150])

    def matches(r: dict) -> bool:
        return (
            r["region"] == region
            and r["status"] == status
            and r["price"] >= min_price
        )

    # guarantee at least two matching rows so the aggregation is non-trivial
    matching = [r for r in rows if matches(r)]
    while len(matching) < 2:
        row = rng.choice(rows)
        row["region"], row["status"] = region, status
        row["price"] = max(row["price"], min_price)
        matching = [r for r in rows if matches(r)]

    metric = rng.choice(["sum_units", "count", "max_price"])
    if metric == "sum_units":
        answer = sum(r["units"] for r in matching)
        metric_text = "the total number of units across"
    elif metric == "count":
        answer = len(matching)
        metric_text = "the number of"
    else:
        answer = max(r["price"] for r in matching)
        metric_text = "the highest price among"

    instruction = (
        f"Compute {metric_text} orders in the {region} region with status "
        f"'{status}' and a price of at least {min_price}. Ignore all other "
        "orders, including any with the same region but a different status. "
        "Answer with the integer only."
    )
    return GeneratedChallenge(
        payload=DataChallenge(family="data", rows=rows, instruction=instruction),
        answer=str(answer),
        answer_format="integer",
    )
