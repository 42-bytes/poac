# PoAC Threat Model

Version 0.1.0 (prototype). Companion to `protocol.md`.

## 1. Assets

- **A1** Admission decision: "this session demonstrated tier Cn capability".
- **A2** Portable receipts and the issuer signing key.
- **A3** Challenge corpus/generators (secrecy is *not* assumed — see D4).
- **A4** Availability of the verifier service.
- **A5** Privacy of provers (minimal data retention).

## 2. Adversary profiles

| ID | Profile | Capabilities |
|----|---------|--------------|
| P1 | Unaided human | browser, keyboard, domain expertise |
| P2 | Human + AI relay | copies challenges into a chat assistant, pastes answers back |
| P3 | Deterministic script | HTTP + parsing + arbitrary local computation, no LLM |
| P4 | LLM-forwarding script | pipes text to an LLM API, no code execution/action loop |
| P5 | Full agent (adversarial) | LLM + tools + HTTP; observationally identical to a legitimate agent |
| P6 | Credential thief | intercepts/steals receipts, replays presentations |
| P7 | Infrastructure attacker | floods sessions, inflates RTT, abuses generation cost |

## 3. Security goals and non-goals

Goals:

- **G1** P1 and P2 fail C1+ with overwhelming probability (timing separation).
- **G2** P3 fails C1+ (reasoning necessity), acknowledging prototype
  limitation L2 below.
- **G3** P4 fails families requiring action/multi-round state under deadline.
- **G4** P6 cannot reuse a receipt: holder proof-of-possession + nonce/aud
  binding + short expiry.
- **G5** No information the verifier stores identifies a prover beyond what
  the prover submitted (key thumbprint, timing, scores).

Non-goals (impossible or out of scope — MUST be restated wherever receipts
are consumed):

- **N1** Proving no human origin/ownership. Impossible on an open network:
  an accepted autonomous agent launched by a human produces an identical
  transcript.
- **N2** Excluding P5 (capable adversarial agents). PoAC verifies
  capability, not intent.
- **N3** Preventing post-issuance key delegation (holder hands its key to
  someone else). Mitigated only by short expiry.
- **N4** Physical distance bounding. Internet RTT jitter makes cryptographic
  distance bounding unachievable at the application layer; we use a capped
  network allowance instead.

## 4. Attacks and mitigations

| Attack | Profile | Mitigation |
|--------|---------|------------|
| Slow, careful human solving | P1 | per-round + whole-session server-measured deadlines calibrated below the human reading lower bound |
| Fast copy/paste relay | P2 | deadlines sized below measured relay round-trip; multi-round chaining multiplies relay overhead per session |
| Template solver for one family | P3 | family selection is unpredictable per round (HMAC chain); C2+ mixes ≥ 3 families; NL surface variation; (residual risk: L2) |
| Answer precomputation / replay of challenge | P3 | per-session seeds from CSPRNG; nonce per round; one-time session state |
| Parallel solving of all rounds | P3/P5 | round n+1 exists only after round n's answer hash is server-verified |
| LLM API forwarding without action loop | P4 | rounds delivered only via HTTP with per-round nonces and deadlines; cross-round references require retained state |
| Receipt replay to another platform | P6 | KB-JWT binds `aud` + verifier `nonce` + `receipt_hash`; verifiers reject reused nonces |
| Receipt tampering / claim inflation | P6 | issuer JWS over all claims; EdDSA only; JWKS pinned by URL |
| Algorithm confusion (`alg` swap) | P6 | verifier accepts exactly `EdDSA`; `typ` values pinned |
| Stolen receipt without key | P6 | `cnf.jkt` thumbprint check against the KB signing key |
| RTT inflation ("slow network") | P7 | fixed capped allowance added server-side; client-asserted latency ignored |
| Session flooding / generation cost abuse | P7 | per-IP and global rate limits, bounded session TTL, cheap seeded generation (no LLM at runtime) |
| Oversized/malformed payloads | P7 | strict schemas, unknown fields rejected, body size caps |
| Malicious Lean submission (elaboration-time code execution, FFI, metaprogramming) | P3/P5 | forbidden-token screen before compilation (`sorry`, `axiom`, `macro`, `elab`, `import`, `#` commands, `unsafe`, `extern`, `native_decide`, attributes, `IO.`/`Lean.`/`System.` namespaces); time-limited subprocess with minimal env; container isolation additionally required for production (L7) |
| `sorry`/axiom smuggling in a proof | P3/P5 | axiom audit: `#print axioms poac_target` must report a subset of Lean's three standard axioms — catches `sorry` (exit code 0!) and any obfuscated `sorryAx` route |
| Kernel-check DoS (slow-to-elaborate submissions, C4/C5 floods) | P7 | hard subprocess timeout (20 s) and memory cap per check; at most `POAC_KERNEL_SLOTS` concurrent Lean processes (semaphore) and `POAC_MAX_KERNEL_SESSIONS` active kernel-tier sessions (admission 503); rate limits as for all sessions |

## 5. Known prototype limitations (carry into the gate report)

- **L1** Timing budgets are design targets until the harness measures real
  agent and relay latencies (milestone 7).
- **L2** Template-based generators mean a source-aware adversary can write
  family-specific deterministic solvers. Acceptable for the prototype;
  production requires a private, rotated, LLM-authored corpus with
  adversarial screening (Phase 2). *Phase 2 status:* `poac.corpus`
  implements the corpus for `nlu`/`logic`/`data` with code-derived answers,
  independent read-back and a reject-if-template-solvable gate
  (`docs/corpus.md`). Residual: `code`/`diagram`/`proof` remain templated;
  a corpus-backed verifier that runs dry silently falls back to templates
  (counted and logged); blind-script measurement against a real corpus is
  pending (track B2).
- **L3** In-memory session store: no durability, single process. *Phase 2
  status:* SQLite-backed session and nonce stores for multi-replica
  deployments (`docs/persistence.md`); PostgreSQL/Redis remain a
  `SessionStore`/`NonceStore` implementation away.
- **L4** Issuer key on local disk for the prototype. Phase 2: KMS/HSM.
- **L5** Human/relay failure counts are small-sample; report confidence
  intervals, never "proven impossible".
- **L6** I2 (registered keys) is recorded but not cryptographically verified
  against an external Web Bot Auth directory in the prototype.
- **L7** The Lean validator (`proof` family, tier C4) relies on token
  screening + subprocess timeouts only. Elaboration of untrusted Lean is a
  larger attack surface than string comparison; production requires running
  the checker in a locked-down container (no network, read-only FS, memory
  limits). The `proof` proposition grammar is also small (see L2).

## 6. Privacy

The verifier stores per session: session id, tier, family sequence, per-round
timing, pass/fail, holder key thumbprint (if I1+). No IP retention beyond
transient rate-limit windows; no content of failed answers is logged beyond
a hash. Benchmarks export anonymized aggregates only.

The `/play` human-trials log additionally carries two pseudonymous source
tags per row: `src` = HMAC(key, address) and `net` = HMAC(key, /24 or /64),
truncated to 64 bits, with the key derived from the server secret. They
exist so an operator can cluster and purge a spamming source
(`poac-trials sources`, `poac-trials purge --src|--net`); the address itself
is never written, the tags are not reversible without the secret, and
rotating the secret unlinks all earlier rows. The page discloses this.

Rate limits are keyed on the client address as seen through the reverse
proxy (`POAC_TRUST_PROXY_HEADERS=1`, set by the compose stack where only
Caddy can reach the verifier). Without it every visitor would share the
proxy's address — one bucket for everyone.
