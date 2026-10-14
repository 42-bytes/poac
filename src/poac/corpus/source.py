"""``ChallengeSource`` that serves corpus instances, templates as fallback.

Families without a corpus (code, diagram, proof) and any (family,
difficulty) bucket that has run dry fall back to the seeded template
generator. Fallbacks are counted so an operator can see when the corpus
needs refilling — a verifier silently serving templates is back at
limitation L2.
"""

from __future__ import annotations

import logging
import random
import threading

from poac.challenges.base import GeneratedChallenge
from poac.challenges.source import ChallengeSource, TemplateSource
from poac.corpus.specs import CORPUS_FAMILIES
from poac.corpus.store import CorpusStore

log = logging.getLogger("poac.corpus")


class CorpusSource:
    def __init__(
        self,
        store: CorpusStore,
        fallback: ChallengeSource | None = None,
        families: tuple[str, ...] = CORPUS_FAMILIES,
    ):
        self._store = store
        self._fallback = fallback or TemplateSource()
        self._families = set(families)
        self._lock = threading.Lock()
        self.fallbacks: dict[tuple[str, int], int] = {}
        self.served: int = 0

    def draw(self, family: str, seed: bytes, difficulty: int) -> GeneratedChallenge:
        if family in self._families:
            rng = random.Random(int.from_bytes(seed, "big"))
            inst = self._store.draw(family, max(0, min(difficulty, 3)), rng)
            if inst is not None:
                with self._lock:
                    self.served += 1
                return inst.to_generated()
            with self._lock:
                self.fallbacks[(family, difficulty)] = self.fallbacks.get((family, difficulty), 0) + 1
            log.warning("corpus empty for %s/d%d; serving template (L2)", family, difficulty)
        return self._fallback.draw(family, seed, difficulty)
