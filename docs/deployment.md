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
deployments load a persisted key (`--issuer-key-file`) or, preferably,
keep the private key in AWS KMS so it never exists on the host:

```bash
AWS_PROFILE=admin ./deploy/aws-kms-setup.sh   # once: creates the keys + a sign-only IAM user
# paste the printed POAC_KMS_* / AWS_* lines into .env, then docker compose up -d
```

With `POAC_KMS_ED25519_KEY` set the verifier signs each receipt with one
`kms:Sign` call (`ED25519_SHA_512`, PureEdDSA over the JWS signing input)
and builds the JWKS from the KMS public key. The IAM identity on the host
can sign and read public keys and nothing else; it cannot export, rotate
or delete the key. If KMS is unreachable a passed session returns 503
("receipt signing unavailable") — never an unsigned or locally-signed
receipt.

### Switching from a local key to KMS, and rotating

The JWKS lists the current key first and any *previous* keys after it. On
startup with both `--kms-key` and an existing `--issuer-key-file`, the
local key's public half is published as a previous key, so receipts
issued before the switch keep verifying until they expire (TTL 300 s).
After one TTL the local key file can be deleted (keep an offline encrypted
copy per `backup-secrets.sh`). To rotate a KMS key: create a new one with
the setup script's `ensure_key`, point `POAC_KMS_ED25519_KEY` at it, and
list the old key's JWK under `previous_keys` for one TTL. Relying parties
that cache the JWKS should honour `kid` and refetch on an unknown `kid`.

## State

Sessions and verify nonces are in-memory by default (single replica). For
multiple replicas use the SQLite-backed stores (`docs/persistence.md`).

## Challenge corpus

Without `--corpus-db` (`POAC_CORPUS_DB`) every round comes from the public
template generators (limitation L2). Build a corpus with `poac-corpus`,
mount it on a writable volume (every draw updates exposure counters, so
the read-only root will not do) and point the verifier at it; see
`docs/corpus.md`.
