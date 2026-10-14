# Private challenge corpus

Closes threat-model limitation L2 for the `nlu`, `logic` and `data`
families. `code`, `diagram` and `proof` still come from the seeded
template generators (their anti-script strength is structural, see
`docs/protocol.md` §5).

## Principle: the LLM writes prose, never answers

```
sample spec (code)  ->  render (LLM A)  ->  read back (LLM B)  ->  gates  ->  store
     hidden structure      prose only       structure again
     + answer                                + its own answer
```

1. **Spec** — the verifier samples the hidden structure itself: which nodes
   were patched on which day, the permutation behind a line-up puzzle, the
   filter and metric over a table. The answer is a pure function of the
   spec (`poac/corpus/specs.py`).
2. **Render** — an author turns the spec into a fresh narrative, statement
   or instruction under a random theme. Pydantic AI with a structured
   output model; the author is told every fact it must state and that it
   must not state the answer.
3. **Read back** — an independent reader (ideally another vendor's model)
   extracts the structure from the prose alone and answers the question,
   also as structured output.
4. **Gates** (`poac/corpus/build.py`), all required:
   * read-back equals the spec field by field and the reader's answer equals
     the code-derived answer — this rejects hallucinated facts, dropped
     constraints, ambiguous phrasing;
   * the public-template reference solver (`poac/reference/solver.py`)
     **fails** on the payload — this rejects renderings that are
     template-shaped and therefore script-solvable;
   * the payload validates against the strict wire model.

What is stored is the payload plus the **spec-derived** answer. At runtime
the verifier does the same exact normalized match it always did; no model
is in the loop while a session is open.

## Exposure, retirement, rotation

Each instance records how often it has been served. Draws take the
least-exposed instance in the requested (family, difficulty) bucket, random
among ties, and retire it at `--max-exposures` (default 5). Whole batches
can be retired (`poac-corpus retire --batch 2026-09`) once a new batch is in
place. When a bucket is empty the source falls back to the template
generator and logs a warning plus a counter (`CorpusSource.fallbacks`); an
operator should treat that as "L2 is back" for that bucket.

Pick `--max-exposures` against your threat: an attacker who solves an
instance once (with a real model) can replay the answer on re-exposure, so
a low cap costs corpus but shrinks that window. Per-holder-key rate limits
bound how many instances one key can harvest.

## Operating it

```sh
pip install -e ".[llm]"                        # pydantic-ai-slim
export OPENAI_API_KEY=... ANTHROPIC_API_KEY=... # whichever vendors you use
poac-corpus --db corpus.sqlite build \
    --model openai:gpt-5.2 --readback-model anthropic:claude-opus-4-6 \
    --count 50 --batch 2026-10
poac-corpus --db corpus.sqlite stats
poac-verifier --corpus-db corpus.sqlite ...     # or POAC_CORPUS_DB
```

`build --author stub` runs the pipeline offline with a deterministic
paraphraser; it exercises every gate and is what the tests use, but its
surface form is regular and must not be deployed.

The build prints acceptance per bucket and the first rejection reasons
(`readback mismatch: cutoff 14 != 15`, `solvable by public-template
reference solver`, …) so prompt or model problems are visible immediately.

## What this does and does not prove

* It guarantees every stored instance has exactly one code-derived answer
  that an independent reader also reaches from the prose. It does not
  guarantee the prose is *hard*; difficulty still comes from the spec
  (number of candidates, constraints, rows) and the deadline.
* The gate against the reference solver only proves the instance is not
  solvable by *that* solver. A determined adversary can still write a
  parser for a specific model's house style; rotation and theme variety
  raise the cost, they do not remove it. Track B2 measures this with blind
  scripts against a real corpus.
