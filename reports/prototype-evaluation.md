# PoAC Prototype — Evaluation Report

Date: 2026-09-04 (prototype gate) · **updated 2026-10-14 (phase 2:
private corpus + frontier-agent trials)** · Protocol 0.2.0
Companion docs: `docs/protocol.md`, `docs/threat-model.md`, `docs/corpus.md`.

## 0. Phase-2 update (2026-10-14): measured, not assumed

Everything in §1–§6 below was measured against the *public template*
generators and is kept for the record. Since then the verifier serves
rounds from a private LLM-authored corpus (`docs/corpus.md`: 239
instances, batch `2026-10`, render gpt-5-mini → independent read-back
claude-sonnet-4.6 → gates), tiers C4/C5 are live, and the public instance
runs at `https://poac.42bytes.eu`. All rows below: in-process transport,
sequential sessions, corpus `2026-10`, JSON in this directory
(`bench-*-corpus.json`, `bench-llm-*-C4.json`).

### 0.1 Scripts and the source-aware oracle against the corpus

| Client | Tier | Pass | Wilson 95% CI | Failure | Reading |
|---|---|---|---|---|---|
| reference-solver (source-aware oracle) | C1 | 0/200 | [0%, 1.9%] | all `wrong_answer` | **L2 closed**: oracle was 100/100 on templates |
| reference-solver (source-aware oracle) | C2 | 0/200 | [0%, 1.9%] | all `wrong_answer` | |
| script-random / script-keyword | C1 | 0/200 each | [0%, 1.9%] | all `wrong_answer` | criterion 3 holds on the corpus |
| script-random / script-keyword | C2 | 0/200 each | [0%, 1.9%] | all `wrong_answer` | |

### 0.2 Frontier agents against the corpus (one-shot, no tools, no retries)

| Agent (via OpenRouter) | C1 | C2 | C3 | C4 (Lean) | C5 (all six) | solve p50 / p95 |
|---|---|---|---|---|---|---|
| Claude Opus 5.5 | 10/10 | 10/10 | 10/10 | 5/5 | 5/5 | 4.4–7.2 s / 8.3–10.7 s |
| Gemini 4 Argon | 10/10 | 10/10 | 10/10 | 5/5 | 5/5 | 2.4–4.3 s / 5.2–7.7 s |
| GPT-5.5 | 10/10 | 10/10 | 9/10 (1 wrong) | 0/5 (non-compiling `simp` proofs) | 2/5 (3 wrong; the `proof` round) | 2.9–4.4 s / 6.9–18.7 s |
| gpt-5-mini | 30/30 | 23/30 (5 timeout, 2 wrong) | — | — | — | 6.0–7.7 s / 12.7–20.8 s |
| Grok 4.7 | 7/10 (3 timeout) | 3/10 (5 timeout, 2 expired) | 0/10 (10 timeout) | — | — | 7–26 s / 38–50 s |

Pooled over Opus 5.5 + Gemini 4 + GPT-5.5 at C1: **30/30**, Wilson 95% CI
[88.6%, 100%] — **criterion 1 met** for current frontier models. Per-model
C1 10/10 has CI [72.2%, 100%]; 30-session per-model runs are queued.

Readings:

- Capability, not vocabulary, is what separates the rows: every Grok 4.7
  failure and every gpt-5-mini C2 failure is a *timeout* against the
  15–20 s round budgets, none a parse or protocol error. A slower
  reasoning model is slower than the deadline, not confused by the task.
  This is limitation **L1** made concrete: tier budgets are a knob that
  trades inclusivity of slower models for distance from the human/relay
  floor (§4), and the floor is still unmeasured.
- The C4 split (Opus/Gemini 5/5, GPT-5.5 0/5) is about one-shot Lean
  without compiler feedback; an agent with a local `lean` loop would close
  it. C4/C5 therefore measure "can write kernel-checked proofs blind",
  which is a stricter claim than the tier name suggests; recorded in
  `protocol.md` §2.1.
- C5 (6 rounds, each family once, 30 s each) costs Opus/Gemini nothing
  extra: pass rates and per-round solve times match C1–C3. GPT-5.5 drops
  to 2/5 because C5 contains one `proof` round and it fails that one blind.
  The tier's value is coverage: it exposes a family-specific gap that C1–C3
  hide.
- Harness lesson: 12 concurrent sessions on one OpenRouter key produced
  HTTP 429s that the first run recorded as instant wrong answers. The
  harness now reports `client_error_rounds`; all rows above were rerun
  sequentially with 0 client errors except Grok C2/C3 (1 each, noted).

### 0.3 Acceptance criteria, phase 2

| Criterion | Status |
|---|---|
| 1. Agent pass rate ≥95% at C1 | **MET** for frontier models (30/30 pooled, CI lower bound 88.6%; 10/10 per model) — not met for Grok 4.7 (timeouts) |
| 2. Unaided human/relay pass ≈0% at C1+ | PENDING — needs volunteers against `poac.42bytes.eu` |
| 3. Blind script pass <2% at C1 | **MET** on the corpus — 0/400, upper CI 1.9%; source-aware oracle also 0/400 |
| 4. Receipt theft unusable without holder key | **MET** — adversarial suite unchanged; `poac.rp` end-to-end tests add replay/aud/tier checks |
| 5. Verifier stable under load, no answer leakage | **MET** — corpus answers never leave the store; public instance served all trials |

### 0.4 Competitor framing (scoped honestly)

Every agent-gating scheme we found (Web Bot Auth key directories, agent
registries, "agent-only" forums' self-declared gates) answers *who signed
this* or *who registered*. None measures *what the holder can do under a
deadline*. PoAC is complementary: the receipt's `cnf.jkt` can be the same
key as a Web Bot Auth signature (`docs/standards-binding.md`). The honest
scope of our adversary claims: blind scripts and source-aware scripts
(0/800 on the corpus) are measured; human relay is not yet; a
*tool-equipped* agent that is itself a frontier model is not an adversary
in this model — it is the intended user.

## 1. What was evaluated

The full prototype stack: five deterministic challenge families, HMAC-chained
timed sessions (C0–C3), Ed25519 holder-bound receipts with key-binding
presentations, discovery surfaces, and the FastAPI verifier. All measurements
below were produced by `benchmarks/run_benchmark.py` (in-process transport,
Apple Silicon dev machine) and are reproducible from the JSON files in this
directory.

## 2. Results

| Client | Tier | Pass | Wilson 95% CI | Session p50 | Notes |
|---|---|---|---|---|---|
| reference-solver (oracle) | C1 | 100/100 | [96.3%, 100%] | 4.8 ms | source-aware script |
| reference-solver (oracle) | C2 | 50/50 | [92.9%, 100%] | 47.6 ms | 8-way concurrent |
| reference-solver (oracle) | C3 | 50/50 | [92.9%, 100%] | 8.8 ms | |
| script-random (blind) | C1 | 0/200 | [0%, 1.9%] | 2.3 ms | all `wrong_answer` |
| script-keyword (blind) | C1 | 0/200 | [0%, 1.9%] | 2.3 ms | all `wrong_answer` |
| script-keyword (blind) | C2 | 0/100 | [0%, 3.7%] | 2.3 ms | all `wrong_answer` |
| reference-solver (oracle) | C4 | 30/30 | [88.7%, 100%] | 741 ms | 3 Lean kernel checks/session |
| blind tactic spam (`first \| decide \| omega \| simp`) | C4 | 0/100 | [0%, 7.1%] | 231 ms | all `wrong_answer`: induction goals resist definition-blind tactics |

Test suite: **225 passed** (contracts, family properties + independent
answer re-verification, session orchestration incl. timing/replay/nonce
attacks, adversarial credential suite, Lean validator security tests,
end-to-end HTTP, discovery). Dependency scan: `pip-audit` — no known
vulnerabilities.

## 3. Key findings

1. **Protocol overhead is negligible.** A full C2 session (4 rounds,
   generation + validation + receipt signing) completes in ~50 ms of server
   time. Timing budgets are entirely available to the prover; the verifier
   adds milliseconds. Sustained 8-way concurrency showed no errors.
2. **Blind scripts fail completely** (0/500 across configurations). The
   distractor construction (uniform sentiment, misleading preliminary
   conclusion, filter-violating rows) defeats frequency and positional
   heuristics; every failure was `wrong_answer`, none `timeout`, meaning the
   families — not the clock — stopped them.
3. **Limitation L2 confirmed empirically.** The source-aware reference
   solver passes 100% at every tier with ~0.1 ms solve times. Because the
   prototype's generators are public templates, a motivated scripter could
   reimplement them. This is the known, accepted prototype limitation; the
   production phase requires a private, rotated, LLM-authored corpus
   (offline authoring + deterministic validation) before any adversarial
   deployment.
4. **The formal tier (C4, added post-gate-draft) validates via the Lean
   kernel.** Fresh seeded propositions in core Lean 4 (v4.33.1, the same
   toolchain that checked the FLT formalization); submissions are
   token-screened, compiled in a time-limited subprocess, and accepted only
   if the axiom audit reports Lean's three standard axioms at most —
   necessary because `sorry` exits 0 with only a warning. The oracle passes
   30/30; blind tactic spam fails 0/100 because difficulty-2+ goals need
   induction over challenge-specific recursive definitions. Kernel checks
   run outside the orchestrator lock (~230 ms each), so concurrent sessions
   are not serialized. Residual risks recorded as L7 (elaboration attack
   surface — containerize for production) and L2 (small proposition grammar).
5. **The oracle sweep caught a real generator bug.** At difficulty 3,
   diagram weight labels stacked near the circle center (all long chords
   pass close to it), making ~13% of dense instances ambiguous *for any
   reader*. Fixed by placing labels 30% along each edge plus a
   generation-time separation check that regenerates until unambiguous.
   Lesson recorded: every family must ship with a payload-only oracle and a
   large seeded sweep; ambiguity shows up only at scale.

## 4. Pending evidence (requires resources not available in this run)

- **LLM-agent trials** (acceptance criterion 1: ≥95% pass at C1 for a
  competent agent): harness ready via
  `python -m benchmarks.run_benchmark --client llm --model openai:<model> --tier C1 --sessions 30`
  — needs provider API keys. Also measures per-session token cost.
- **Human and human-relay trials** (acceptance criterion 2): requires
  volunteer sessions against a deployed instance
  (`--base-url`), including copy-paste relay to a chat assistant. The C1
  20 s/round budget is designed to be below the read-narrative → relay →
  paste-back floor, but this must be measured, not assumed.
- **Network-transport timing calibration**: rerun benchmarks against a
  deployed instance to validate the 2 s network allowance.

## 5. Acceptance criteria status

| Criterion | Status |
|---|---|
| 1. Agent pass rate ≥95% at C1 | PENDING — needs LLM trials (harness ready) |
| 2. Unaided human/relay pass ≈0% at C1+ | PENDING — needs live trials; script proxies at 0/500 |
| 3. Blind script pass <2% at C1 | **MET** — 0/400, upper CI 1.9% |
| 4. Receipt theft unusable without holder key | **MET** — adversarial suite (13 attack tests) |
| 5. Verifier stable under load, no answer leakage | **MET** — concurrency run + leakage tests |

## 6. Recommendation

The prototype validates the protocol mechanics: deterministic families,
chained timed sessions, and holder-bound portable receipts all behave as
specified under test and adversarial probing. Before any production
planning is approved, criteria 1 and 2 need live evidence (LLM keys and a
small deployed trial). Recommend: run those two trials, then hold the gate
review. Production phase must additionally address L2 (private rotated
corpus) as designed in `docs/protocol.md` §5 (Phase 2).
