# Deployment

## Single node (Docker)

```bash
docker compose up --build
curl -s localhost:8000/.well-known/agent-capability.json | python -m json.tool
```

`docker-compose.yml` runs the verifier read-only, without capabilities, with
a tmpfs `/tmp` for Lean scratch files, memory and pid ceilings, and on an
internal network reachable only through the Caddy reverse proxy. Set
`POAC_BASE_URL` to the public URL — it becomes the receipt `iss` and the
manifest's issuer field, so relying platforms can locate the JWKS.

## Lean kernel isolation

The `proof` family elaborates untrusted text. Defence layers, inner to
outer:

1. token screen before compilation (`proof_check.FORBIDDEN_TOKENS`);
2. per-check subprocess with a 20 s wall-clock timeout and Lean's own heap
   cap `--memory=<MB>` (`POAC_LEAN_MAX_MEMORY_MB`, default 1024). POSIX
   rlimits are not usable: Lean reserves very large thread stacks and
   aborts at startup under `RLIMIT_AS`/`RLIMIT_DATA` even at several GB;
3. the runtime image contains only the pinned toolchain directory, not
   `elan`, so nothing can fetch or switch toolchains;
4. container: non-root, `cap_drop: ALL`, `no-new-privileges`, read-only
   root, bounded tmpfs, `pids_limit`, `mem_limit`;
5. network: internal-only; the verifier initiates no outbound connections.

For stricter egress isolation run kernel checks in a separate worker
container on a `--network none` network, fed over a shared volume. That
split is not implemented; the single-container profile above is adequate
for a public demo, not for a high-value gate.

## Issuer key

`create_app()` generates a fresh Ed25519 issuer key per process. Receipts
survive only as long as that key is in the JWKS, so a restart invalidates
outstanding receipts (they are short-lived by design). For stable
deployments load a persisted key — see `ReceiptIssuer(key=...)` — and keep
the previous key in the JWKS for one receipt TTL after rotation.

## State

Sessions and verify nonces are in-memory by default (single replica). For
multiple replicas use the SQLite-backed stores (`docs/persistence.md`).

## Challenge corpus

Without `--corpus-db` (`POAC_CORPUS_DB`) every round comes from the public
template generators (limitation L2). Build a corpus with `poac-corpus`,
mount it on a writable volume (every draw updates exposure counters, so
the read-only root will not do) and point the verifier at it; see
`docs/corpus.md`.
