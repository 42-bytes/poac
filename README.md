# PoAC — Proof of Agent Capability

A **reverse CAPTCHA**: instead of proving you are human, you prove you are a
capable machine. The verifier issues multi-round challenges under
server-measured deadlines that are trivial for an autonomous AI agent
(LLM + code execution + HTTP loop) but cannot be completed by a person — even
one copy-pasting into a chat assistant — before the clock runs out. Passing
yields a short-lived, holder-key-bound capability receipt that can be
presented to third-party platforms.

Status: **prototype, not yet a security boundary.** See
[Status and known limitations](#status-and-known-limitations).

## What a passed session proves — and what it does not

> The holder of private key K completed challenge suite S at tier Cn within
> the server-measured timing budget at time T.

It does **not** prove absence of human origin or ownership, benign intent,
or that the key was not delegated afterwards. Relying platforms must layer
their own authorization and abuse controls on top. See
[`docs/protocol.md`](docs/protocol.md) and
[`docs/threat-model.md`](docs/threat-model.md) for the full honest-claims
analysis.

## How it works

1. **Session** — `POST /v1/sessions` with a tier (`C0`–`C4`) and optionally
   your Ed25519 public JWK (for a portable receipt). The response contains
   round 1: one challenge, a nonce, and a time budget.
2. **Rounds** — solve and `POST /v1/sessions/{id}/rounds/{n}` before the
   server-side deadline. Each next round is derived from an HMAC over the
   server secret, session id, and your *verified* previous answer — rounds
   cannot be precomputed or solved in parallel. Any violation (timeout,
   wrong nonce, replay, wrong answer) permanently fails the session.
3. **Receipt** — passing the final round returns an Ed25519-signed JWS with
   the measured facts (tier, families, per-round latencies) and a `cnf.jkt`
   binding to your key.
4. **Presentation** — to prove capability to a relying platform, obtain a
   verifier nonce (`GET /v1/verify/nonce`), then sign a key-binding JWT over
   the platform's audience + that nonce + the receipt hash (DPoP-style). A
   stolen receipt is useless without the private key. Platforms verify via
   `POST /v1/verify` or offline against the JWKS.

## Challenge families

All instances are validated deterministically — no LLM judging at runtime,
no subjective grading.

| Family | Task | Human bottleneck |
|---|---|---|
| `nlu` | multi-hop inference over a long synthetic incident report with distractors | reading speed |
| `code` | predict the printed output of a generated Python program | mental execution |
| `logic` | ordering puzzle with a provably unique solution | constraint search |
| `data` | filtered aggregation over dozens of table rows | scanning + arithmetic |
| `diagram` | cheapest path in a weighted graph rendered as SVG | reading raw SVG |
| `proof` | prove a fresh proposition in core Lean 4; the Lean kernel is the validator | authoring formal proofs in 40 s |

Tiers scale rounds, difficulty, and budgets: `C0` (1 round, 60 s, sanity
check) through `C3` (6 rounds, 15 s each, all short-answer families mixed),
plus the formal tier `C4` (3 Lean proof rounds, 40 s each — offered only
when the verifier host has the pinned Lean toolchain; install via
[elan](https://github.com/leanprover/elan), auto-detected at startup).
Submissions to `C4` are token-screened, compiled in a time-limited
subprocess, and accepted only if an axiom audit shows nothing beyond Lean's
three standard axioms.

## Install and run

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
poac-verifier --port 8000            # or: uvicorn --factory poac.api.app:create_app
pytest                               # 292 tests; Lean-dependent ones skip without a toolchain
```

One replica needs no configuration. For several replicas share a SQLite
state file, the server secret and the issuer key — see
[`docs/persistence.md`](docs/persistence.md); for the hardened container see
[`docs/deployment.md`](docs/deployment.md).

Then explore:

- `http://localhost:8000/` — notice for human visitors
- `http://localhost:8000/llms.txt` — agent instructions
- `http://localhost:8000/.well-known/agent-capability.json` — machine manifest
- `http://localhost:8000/openapi.json` — API schemas
- `http://localhost:8000/.well-known/jwks.json` — issuer public keys

## Benchmarks

The evaluation harness plays full sessions with different prover profiles:

```bash
# source-aware oracle (protocol overhead; demonstrates threat-model limit L2)
python -m benchmarks.run_benchmark --client reference --tier C2 --sessions 50

# blind script baselines (should fail ~always)
python -m benchmarks.run_benchmark --client script-keyword --tier C1 --sessions 200

# real LLM agent via Pydantic AI (needs provider API key + llm extra)
pip install -e ".[llm]"
python -m benchmarks.run_benchmark --client llm --model openai:gpt-5.2 --tier C1 --sessions 30

# against a deployed instance instead of in-process
python -m benchmarks.run_benchmark --client reference --tier C1 --sessions 20 --base-url https://poac.example
```

Results land in `reports/bench-*.json`. Current findings (details in
[`reports/prototype-evaluation.md`](reports/prototype-evaluation.md)):
blind scripts pass 0/500 short-answer sessions and 0/100 formal sessions
(blind tactic spam cannot close induction goals), the oracle passes 100%
with ~50 ms of server time per C2 session (~740 ms per C4 session including
kernel checks), and live LLM/human trials are pending.

## Security review

`tests/test_adversarial.py` is a red-team suite: 42 attacks across the
challenge layer, session protocol, credential forgery, and the Lean kernel
path. All fail closed. Findings and accepted trade-offs are in
[`docs/threat-model.md`](docs/threat-model.md).

## Status and known limitations

Prototype. The built-in challenge generators are public templates, so a
source-aware script can pass (limitation L2, demonstrated by the reference
solver). The production design replaces them with a private, rotated,
LLM-authored corpus validated deterministically — see `docs/protocol.md`
§5. Receipts are honest about what they prove. Do not deploy this as a
security boundary yet.

## Layout

```
docs/protocol.md           protocol spec, tiers, acceptance criteria
docs/threat-model.md       adversary profiles, attacks, limitations
docs/deployment.md         hardened container (pinned Lean, no network, read-only)
docs/persistence.md        shared SQLite state for multi-replica deployments
src/poac/protocol/         strict Pydantic wire contracts
src/poac/challenges/       six generators + registry + Lean kernel validator + source seam
src/poac/sessions/         tier config, HMAC-chained orchestration, memory/SQLite stores
src/poac/credentials/      Ed25519 receipt issuance + KB-JWT verification
src/poac/api/              FastAPI app factory + console entry point
src/poac/discovery/        llms.txt, human notice, capability manifest
src/poac/reference/        payload-only oracle solver (evaluation only)
benchmarks/                prover clients + harness + stats
tests/                     contract, property, session, credential, kernel, red-team suites
reports/                   benchmark JSON + gate evaluation report
```

## License

Apache-2.0. See [`LICENSE`](LICENSE).
