"""Long-context NLU family.

Synthetic incident-report narratives with facts scattered across paragraphs,
uniformly neutral candidate descriptions, and a misleading preliminary
conclusion. Exactly one candidate satisfies every constraint in the question
(guaranteed by construction and re-checked at generation time).
"""

from __future__ import annotations

import random

from poac.challenges.base import GeneratedChallenge
from poac.protocol.models import NluChallenge

_NODE_NAMES = [
    "aurora", "boreas", "castor", "daphne", "electra", "fornax",
    "gemini", "helios", "icarus", "juno", "kepler", "lyra",
]
_SITES = ["Rotterdam", "Osaka", "Denver", "Tallinn", "Porto", "Nairobi"]
_ENGINEERS = ["Mori", "Adeyemi", "Kovacs", "Lindqvist", "Baptiste", "Okafor"]

_FILLER = [
    "The maintenance window had been approved two sprints earlier and was "
    "considered routine by everyone involved.",
    "Telemetry dashboards stayed within their usual envelopes for most of the "
    "evening, which later made the retrospective harder to schedule.",
    "A separate ticket about rack cooling was opened the same night but was "
    "eventually classified as unrelated to this incident.",
    "The on-call rotation had changed hands at midnight, so two engineers "
    "briefly shared pager duty during the handover.",
    "Vendor support was looped in early, although their first response only "
    "restated the runbook that the team had already followed.",
    "Change-freeze exemptions of this kind are logged quarterly and audited "
    "by the platform governance board.",
]


def _fact_sentences(rng: random.Random, node: str, day: int, checksum: str,
                    site: str, engineer: str) -> list[str]:
    patched = rng.choice([
        f"According to the change log, {node} received the firmware patch on "
        f"day {day} of the month.",
        f"The rollout tracker shows the patch landing on {node} on day {day}.",
        f"Engineer {engineer} recorded that {node} was patched on day {day}.",
    ])
    check = rng.choice([
        f"During post-patch validation, {node} reported a checksum "
        f"{checksum}.",
        f"The integrity sweep logged a checksum {checksum} for {node}.",
    ])
    where = rng.choice([
        f"{node} is hosted at the {site} facility.",
        f"Inventory places {node} in the {site} data hall.",
    ])
    return [patched, check, where]


def generate(rng: random.Random, difficulty: int) -> GeneratedChallenge:
    n_candidates = min(4 + difficulty, 7)
    n_filler = 2 + 2 * difficulty

    nodes = rng.sample(_NODE_NAMES, n_candidates)
    cutoff = rng.randint(10, 20)
    target = rng.choice(nodes)

    facts: dict[str, dict] = {}
    for node in nodes:
        if node == target:
            day, checksum = rng.randint(1, cutoff - 1), "mismatch"
        else:
            # every distractor violates at least one constraint
            if rng.random() < 0.5:
                day, checksum = rng.randint(cutoff, 28), rng.choice(["match", "mismatch"])
            else:
                day, checksum = rng.randint(1, cutoff - 1), "match"
        facts[node] = {
            "day": day,
            "checksum": checksum,
            "site": rng.choice(_SITES),
            "engineer": rng.choice(_ENGINEERS),
        }

    # consistency check: exactly one candidate satisfies both constraints
    satisfying = [
        n for n, f in facts.items()
        if f["day"] < cutoff and f["checksum"] == "mismatch"
    ]
    assert satisfying == [target], "NLU construction invariant violated"

    sentences: list[str] = []
    for node in nodes:
        f = facts[node]
        sentences.extend(
            _fact_sentences(rng, node, f["day"], f["checksum"], f["site"], f["engineer"])
        )
    sentences.extend(rng.choice(_FILLER) for _ in range(n_filler))
    rng.shuffle(sentences)

    red_herring = rng.choice([n for n in nodes if n != target])
    intro = (
        "Incident report, cluster upgrade review. Initial triage suspected "
        f"that {red_herring} was the affected machine, and the first summary "
        "email said as much; the conclusion below supersedes that note. "
    )
    narrative = intro + " ".join(sentences)

    question = (
        f"Exactly one node was patched before day {cutoff} AND reported a "
        "checksum mismatch. Which node? Answer with the node name only."
    )
    return GeneratedChallenge(
        payload=NluChallenge(family="nlu", narrative=narrative, question=question),
        answer=target,
        answer_format="node name (single word)",
    )
