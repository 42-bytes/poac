# Standards binding: carrying PoAC receipts on existing rails

PoAC's own presentation (receipt JWS + key-binding JWT, `/v1/verify`) is
deliberately tiny. This document fixes how the same receipt rides on the
three standards that platforms are already adopting for agent traffic, so a
relying party never has to invent a header format. Nothing here changes
what a receipt proves (see `protocol.md` §1).

Status: **profile v0.1 — normative wording, reference implementation
pending**. The native presentation remains the only path `poac.rp`
implements today.

## 1. Web Bot Auth / HTTP Message Signatures (RFC 9421)

Web Bot Auth (IETF draft `draft-meunier-web-bot-auth-architecture`) has
agents sign each request with RFC 9421 and publish their key in a
directory named by `Signature-Agent`. PoAC slots in as the **capability
attestation for that same key**: the receipt's `cnf.jkt` is the RFC 7638
thumbprint of the Ed25519 key that signs the request, so the request
signature *is* the proof of possession and no KB-JWT is needed.

Request profile:

```
Signature-Input: sig1=("@authority" "@method" "@path" "poac-receipt");
                 created=1760480000; keyid="<jkt>"; alg="ed25519"; nonce="<rp nonce>"
Signature: sig1=:<base64 Ed25519 signature>:
Signature-Agent: "https://agent.example"          # optional, as in Web Bot Auth
PoAC-Receipt: <compact JWS receipt>
```

Rules:

- `keyid` MUST equal the receipt's `cnf.jkt`. The relying party resolves
  the key either from the `Signature-Agent` directory (JWKS, `kid`=jkt) or
  from the receipt holder JWK the agent registered when it created its
  session (verifiers MAY echo `holder_jwk` inside the receipt in a future
  claim; today the agent supplies it via the directory).
- Covered components MUST include `@authority`, `@method`, `@path` and
  `poac-receipt`; `created` MUST be within the relying party's clock
  tolerance (±60 s recommended) and `created` MUST be < receipt `exp`.
- `nonce` SHOULD be a relying-party nonce (obtained from `GET /v1/verify/nonce`
  or the RP's own store) to make presentations single-use; without it the
  RP MUST bound replay by `(keyid, created)` deduplication.
- The RP verifies the receipt exactly as `/v1/verify` does minus the KB-JWT
  step: issuer signature via `/.well-known/jwks.json`, `typ`, `exp`,
  `iss`, then `cnf.jkt == keyid`. A relying party without a local verifier
  MAY still call `POST /v1/verify` by constructing a KB-JWT itself — this
  is **not** permitted, since the RP does not hold the key; use the local
  check or the planned `POST /v1/verify/rfc9421` endpoint instead.

Failure signalling reuses `WWW-Authenticate: PoAC …` from `poac.rp` with
an added `profile="rfc9421"` parameter.

## 2. OAuth 2.0 DPoP (RFC 9449) shape

For platforms that already run DPoP, the receipt is a DPoP-bound token:
`cnf.jkt` is identical in meaning to DPoP's `cnf.jkt`. Present the receipt
as `Authorization: PoAC <receipt>` with a standard `DPoP` proof JWT
(`typ: dpop+jwt`, `htm`, `htu`, `iat`, `jti`, `nonce`, `ath` = SHA-256 of
the receipt). An RP with a DPoP library verifies the proof as usual and
then checks the receipt. This is a drop-in for the PoAC KB-JWT; the two
differ only in claim names (`ath` vs `receipt_hash`, `htu/htm` vs `aud`).

## 3. SD-JWT VC (draft-ietf-oauth-sd-jwt-vc) envelope

For wallet-style ecosystems a receipt can be reissued as an SD-JWT VC:

- `vct`: `https://poac.dev/vct/capability-receipt/1`
- `iss`, `iat`, `exp`, `cnf` copied from the receipt
- claims `capability_tier`, `identity_tier`, `families`, `latency_ms`,
  `session_id` — the latter three selectively disclosable, so an agent can
  show "C3, I1" without revealing which families or timings it saw.
- Key binding uses the SD-JWT KB-JWT (`typ: kb+jwt`, `aud`, `nonce`, `iat`,
  `sd_hash`), which is what PoAC's KB-JWT was modelled on.

The verifier would expose `POST /v1/sessions/{id}/receipt?format=sd-jwt-vc`
to issue this form; no change to the challenge protocol.

## 4. What stays PoAC-specific

- The challenge session itself (`/v1/sessions`, chained rounds, deadlines).
- The tier vocabulary `C0–C5` / `I0–I3` and its measured semantics.
- The 5-minute receipt TTL: standards above carry the receipt, they do not
  extend its life.

## 5. Implementation plan

1. `poac.rp` accepts the RFC 9421 profile (`Signature`/`Signature-Input` +
   `PoAC-Receipt`) alongside the native headers; `poac.client` gains
   `sign_request(method, url, receipt, nonce)`.
2. `POST /v1/verify/rfc9421` for relying parties without a local issuer
   JWKS cache.
3. SD-JWT VC issuance behind a feature flag once a relying party asks.
