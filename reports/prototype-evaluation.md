# PoAC Prototype — Evaluation Report

Date: 2026-09-04 · Suite: `2026.09-proto` · Protocol 0.1.0
Companion docs: `docs/protocol.md`, `docs/threat-model.md`.

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
