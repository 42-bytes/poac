"""Private challenge corpus (phase 2, closes threat-model limitation L2).

The public generators in ``poac.challenges`` are templates: a source-aware
script can parse them. The corpus replaces their *surface text* with
LLM-authored renderings while keeping the ground truth and the answer
entirely code-derived:

    sample spec (code) -> render (LLM) -> read back (LLM, independent)
        -> accept only if readback == spec AND reference solver fails

At runtime nothing changes: the verifier still does an exact match against
the stored, code-derived answer. No LLM is ever consulted while a session
is open.
"""

from poac.corpus.source import CorpusSource
from poac.corpus.store import CorpusInstance, CorpusStore

__all__ = ["CorpusInstance", "CorpusSource", "CorpusStore"]
