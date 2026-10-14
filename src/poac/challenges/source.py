"""Where round instances come from.

``TemplateSource`` builds instances from the seeded generators (public
templates — threat-model limitation L2). ``poac.corpus.CorpusSource`` draws
pre-authored instances from a private corpus and falls back to templates
when none is available for the requested family/difficulty.
"""

from __future__ import annotations

from typing import Protocol

from poac.challenges.base import GeneratedChallenge
from poac.challenges.registry import make_challenge


class ChallengeSource(Protocol):
    def draw(self, family: str, seed: bytes, difficulty: int) -> GeneratedChallenge:
        """Return one instance. Must be deterministic in ``seed`` for templates;
        corpus-backed sources may consume state (exposure counters)."""


class TemplateSource:
    def draw(self, family: str, seed: bytes, difficulty: int) -> GeneratedChallenge:
        return make_challenge(family, seed, difficulty)
