# Proof of Agent Capability (PoAC) — Protocol Specification

Version: 0.1.0 (prototype)
Status: experimental — all parameters subject to empirical calibration
(see `benchmarks/` and `reports/prototype-evaluation.md`).

## 1. Purpose and honest claims

PoAC is a *reverse CAPTCHA*: a timed, multi-round challenge protocol that is
easy for autonomous AI agents (LLM + code execution + HTTP action loop) and
infeasible for unaided humans or humans manually relaying to an AI assistant.

**What a passed PoAC session proves** (and nothing more):

> The holder of private key K completed challenge suite S at tier Cn within
> the server-measured timing budget at time T.

**What it explicitly does NOT prove:**

- that no human launched, owns, prompts, or profits from the agent;
- that the agent is benign;
- that the key was not delegated to another party after issuance;
- that a capable adversarial agent is excluded.

Any consumer of a PoAC receipt MUST treat these as out of scope and layer
its own authorization, reputation, and abuse controls on top.

## 2. Assurance dimensions

PoAC deliberately reports **separate** dimensions instead of one trust score.

### 2.1 Capability tiers (C)

| Tier | Meaning | Rounds | Per-round budget* | Families |
|------|---------|--------|-------------------|----------|
| C0 | automation/computation only | 1 | 60 s | any single computational task |
| C1 | HTTP action + reasoning + cross-round memory | 3 | 20 s | NLU, data, logic |
| C2 | broad capability: rotating families, chained | 4 | 20 s | all 5 short-answer families |
| C3 | frontier: long context, all families, strict | 6 | 15 s | all 5 short-answer families, larger instances |
| C4 | formal: machine-checkable Lean proofs of fresh propositions | 3 | 40 s | `proof` only; offered only when the verifier host has the pinned Lean toolchain |

\* Design targets. The budgets are inputs to calibration, not constants:
the evaluation harness (milestone 7) measures real agent latencies and the
human lower bound and the operator sets budgets inside the measured
separation zone. Server timing is monotonic-clock based; a fixed network
allowance (default 2 s/round) is added, never client-asserted.

### 2.2 Identity assurance (I)

| Tier | Meaning |
|------|---------|
| I0 | anonymous — no key binding requested |
| I1 | receipt bound to an ephemeral holder key (proof-of-possession) |
| I2 | holder key is a registered Web Bot Auth / JWKS-published key |
| I3 | hardware/runtime attestation (out of prototype scope) |

The prototype implements I0 and I1 fully; I2 is a claim slot verified only
syntactically; I3 is documented but not implemented.

### 2.3 Freshness

Receipts are short-lived (`exp - iat` = 300 s for C2/C3, 3600 s for C0/C1 by
default). Verifiers MUST check `exp` and SHOULD require a fresh key-bound
presentation (Section 6) rather than accepting a bare receipt.

## 3. Actors

- **Client (prover):** the entity attempting the challenge. Presumed hostile.
- **Verifier server (issuer):** generates challenges, measures timing,
  validates answers deterministically, issues receipts.
- **Relying platform:** any third party that later accepts a receipt via a
  nonce-bound presentation.

## 4. Session protocol

All bodies are JSON validated against strict schemas (unknown fields
rejected). All schemas are published via OpenAPI.

```
Client                                  Verifier
  |  POST /v1/sessions                     |
  |  {tier, holder_jwk?}                   |
  |---------------------------------------->
  |  201 {session_id, round 1 challenge,   |
  |       deadline, nonce}                 |
  <----------------------------------------|
  |  POST /v1/sessions/{id}/rounds/1       |
  |  {answer, nonce}                       |
  |---------------------------------------->
  |  200 {round 2 challenge, ...} | fail   |
  <----------------------------------------|
  |  ... final round ...                   |
  |  200 {receipt (JWS), score, timing}    |
  <----------------------------------------|
```

Rules:

1. **Key commitment first.** For I1, the holder JWK (Ed25519 OKP) is
   submitted at session creation, before any challenge content is revealed.
2. **One-time state.** A session is single-use; any protocol violation
   (wrong order, replayed nonce, expired deadline, malformed body, oversized
   payload) permanently fails it.
3. **Unpredictable chaining.** The family and instance of round *n+1* are
   derived server-side from `HMAC(server_secret, session_id || n ||
   answer_hash(n))`. Rounds cannot be precomputed or parallelized.
4. **Server-side timing.** Deadlines use the server monotonic clock from
   the instant the challenge body is serialized to the instant the answer
   arrives. Client-claimed latency is ignored.
5. **Deterministic verification.** Short-answer families are checked by
   normalized exact match against a precomputed value. The `proof` family is
   checked by the Lean kernel (exit status + axiom audit) — still fully
   deterministic and objective. No LLM participates in runtime verification.
6. **Bounded feedback.** Failures return the failure class (timeout,
   wrong_answer, protocol_violation) but never the expected answer.

## 5. Challenge families

Six families, each with a seeded deterministic generator and validator
(`src/poac/challenges/`). Difficulty scales with tier.

| Family | Task | Why hard for humans under deadline | Why hard for scripts |
|--------|------|-----------------------------------|---------------------|
| `nlu` | long synthetic narrative with scattered facts, misleading intermediate conclusions; short-string answer | serial reading is 3–5 tokens/s; narratives are 400–1200+ tokens | answer requires coreference + multi-hop inference, not keyword lookup |
| `code` | trace a generated program (loops, conditionals, string/arith ops) and report its output | multi-step mental execution under time pressure | program text is generated, not templated verbatim; still, a Python-executing script can solve it — this family therefore never appears alone above C0 |
| `logic` | constraint puzzle (unique solution by construction) stated in natural language | working-memory bound | NL statement must be parsed into constraints |
| `data` | aggregate/filter a generated JSON dataset per NL instructions | volume × arithmetic under deadline | instructions are NL with distractors |
| `diagram` | properties of a generated SVG graph (paths, degrees, labels) | visual + graph reasoning under deadline | requires SVG parsing + graph reasoning |
| `proof` | prove a fresh, seeded core-Lean-4 proposition; the Lean kernel validates the submission and audits its axioms | authoring correct formal proofs in 40 s is beyond skilled humans; copy-paste relay still requires an assistant to produce Lean that compiles | blind tactic spam (`by first | decide | omega | ...`) fails difficulty-2+ goals, which require induction over challenge-specific recursive definitions |

### 5.1 The `proof` family (tier C4)

Inspired by machine-checked mathematics (e.g. the Lean 4 formalization of
Fermat's Last Theorem): verification cost is decoupled from production cost.
The verifier assembles `preamble + "theorem poac_target : {proposition} :=
{submission}"`, compiles it with a pinned core Lean toolchain (no Mathlib),
and accepts only if compilation succeeds and `#print axioms poac_target`
reports a subset of `{propext, Classical.choice, Quot.sound}` (this catches
`sorry`, which otherwise exits 0 with a warning). Submissions are screened
against metaprogramming/FFI/command tokens before compilation, and the
kernel runs in a time-limited subprocess. Every generated proposition
carries a generator-authored reference proof, so solvability is guaranteed
by construction and swept in tests.

Prototype limitation (documented, accepted): generators are template-based,
so an adversary with full source access can write family-specific solvers.
Anti-script strength in the prototype comes from NL surface variation and
family chaining; production strength requires an LLM-authored, private,
rotated corpus (Phase 2). This applies to the `proof` grammar too: its
current recurrence schemas are enumerable, and Phase 2 requires a broader
proposition space (with each instance still validated by generation-time
kernel checks).

## 6. Receipts and portable presentation

### 6.1 Receipt (issuer → holder)

A compact JWS (EdDSA/Ed25519) signed by the issuer key published at
`/.well-known/jwks.json`:

```json
{
  "iss": "<issuer url>", "sub": "poac-session",
  "jti": "<session id>", "iat": ..., "exp": ...,
  "poac": {
    "version": "0.1.0",
    "capability_tier": "C2",
    "identity_tier": "I1",
    "families": ["nlu", "logic", "data", "diagram"],
    "rounds_passed": 4, "rounds_total": 4,
    "latency_ms": [3120, 2870, 4010, 3555],
    "suite_version": "2026.09-proto"
  },
  "cnf": {"jkt": "<RFC 7638 thumbprint of holder JWK>"}
}
```

`cnf` is present only for I1+. Claims are **measured facts** — no verdicts
like "is_ai".

### 6.2 Presentation (holder → relying platform)

The verifier issues the `nonce`: the holder (or the relying platform on its
behalf) calls `GET /v1/verify/nonce` and receives a one-shot nonce with a
short TTL (120 s, matching the KB-JWT `iat` window). The holder returns the
receipt plus a Key-Binding JWT (`typ: "poac-kb+jwt"`) signed with the holder
key over `{aud, nonce, iat, receipt_hash}` where
`receipt_hash = b64url(sha256(receipt JWS))`. `POST /v1/verify` consumes the
nonce on first use whether or not the presentation verifies; a nonce it did
not issue, or one already consumed, is rejected with a distinct reason.
Relying platforms verifying offline against the JWKS supply their own nonce
and are responsible for its freshness.

Verification (`credentials/presentation.py`) requires, in order: issuer
signature and `exp`; `cnf.jkt` equals the thumbprint of the KB-JWT signing
key; KB `aud`/`nonce` match the verifier's values; `receipt_hash` matches;
KB `iat` within skew. Any failure is a hard reject. Only `EdDSA` is
accepted for both signatures (no algorithm negotiation).

## 7. Discovery

- `/` — human-readable notice: purpose, limitations, alternatives for humans.
- `/llms.txt` — machine-readable overview and entry points.
- `/.well-known/agent-capability.json` — manifest: tiers, budgets,
  endpoints, schema URLs, suite version, honest-claims statement.
- `/.well-known/jwks.json` — issuer public keys.
- HTTP `Link` headers (`rel=describedby`, `rel=service-desc`) on all
  responses.
- OpenAPI at `/openapi.json` and docs at `/docs`.

## 8. Acceptance criteria (prototype gate)

Measured by `benchmarks/` before any production claim:

1. ≥ 100 agent sessions across ≥ 3 model/provider configurations pass C1
   with ≥ 95% session pass rate.
2. Deterministic script baselines (no LLM) achieve 0 passes at C1+ across
   ≥ 200 attempts (report with 95% CI, not as proof).
3. ≥ 30 unaided-human and ≥ 30 human+AI-relay attempts at C1+: 0 passes
   (report with CI).
4. 0 replay/tamper bypasses across the adversarial credential suite.
5. p95 agent latency per round documented per provider and region; budgets
   re-derived from measurements.
6. Cost per session documented (generation + verification + LLM cost of the
   test agent).
