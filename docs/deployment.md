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

`POAC_KMS_MLDSA65_KEY` (the setup script creates this `ML_DSA_65` key too)
additionally enables dual-signed receipts: holders that ask for
`receipt_format: "json-dual"` get Ed25519 + ML-DSA-65 signatures, one
`kms:Sign` each, and the ML-DSA public key is published in the JWKS as an
`AKP` JWK. Compact Ed25519 remains the default; see protocol.md §6.1.

The verifier container has no route to the internet. Its only way out is
the `kms-egress` sidecar in `docker-compose.yml`: a Squid forward proxy
(`deploy/kms-egress.squid.conf.tpl`) on both networks that admits
`CONNECT kms.<POAC_KMS_REGION>.amazonaws.com:443` and denies everything
else (any other host gets `403` from the proxy; plain HTTP has no route at
all). boto3 picks it up via `HTTPS_PROXY`. The Lean subprocess runs with a
scrubbed environment, so neither the proxy variable nor the AWS
credentials reach kernel checks.

### Rotation

The JWKS lists the current key(s) first and *previous* public keys after
them, each until its `retire_at`. Receipts live 300 s, so a 24 h window is
generous and also covers relying parties with a cached JWKS (`PoacGate`
refetches on an unknown `kid`). Previous keys live in
`/data/previous-keys.json`, managed by `poac-keys`; the verifier reads it
at start (`POAC_PREVIOUS_KEYS_FILE`).

KMS-backed issuer (production):

```bash
# 1. laptop, admin creds: mint a replacement key (signer policy covers it by tag)
ED_ALIAS=poac-issuer-ed25519-2027q1 AWS_PROFILE=poac-admin deploy/aws-kms-setup.sh
# 2. server: snapshot the OLD key's public half before switching
docker compose exec verifier poac-keys retire-kms \
    --key "$OLD_ARN" --previous-keys-file /data/previous-keys.json --retire-after 24h
# 3. server: point .env POAC_KMS_ED25519_KEY at the new ARN, then
docker compose up -d verifier
# 4. aws kms schedule-key-deletion --key-id "$OLD_ARN" --pending-window-in-days 7
#    (safe right away: verification uses the snapshotted public key, not KMS)
# 5. take a fresh deploy/backup-secrets.sh bundle — .env changed
```

Drilled live on 2026-10-15: pre-rotation receipt verified after the
switch, new receipts carried the new `kid`, no downtime beyond the
container restart.

Local key file (installs without KMS): `poac-keys rotate-local
--issuer-key-file /data/issuer.jwk --previous-keys-file
/data/previous-keys.json`, then restart. The previous-keys file is written
before the new key replaces the old one, so a crash in between never loses
the old `kid`. `poac-keys show --previous-keys-file …` lists what is
published and what has retired. The same `retire-kms` flow rotates the
ML-DSA-65 key (`PQ_ALIAS=…`, `POAC_KMS_MLDSA65_KEY`).

Switching from a local key to KMS is the same idea done by hand: start
once with both `--kms-key` and the existing `--issuer-key-file`, and the
local key's public half is published as a previous key; after one TTL
drop the file argument and delete the file (keep the `backup-secrets.sh`
bundle).

## Backups and custody

Three things on the server are irreplaceable: `/opt/poac/.env` (server
secret, KMS signer credentials), the private corpus `corpus.sqlite`, and —
until it is retired — the local issuer key `issuer.jwk`. The human-trial
log rides along because it cannot be regenerated either. KMS keys
themselves are not in the bundle: they never leave AWS, which is the point;
if the account were lost, receipts in flight (TTL 300 s) are the only
casualty and a new key is one `aws-kms-setup.sh` run away.

```bash
brew install age
deploy/backup-secrets.sh          # from your laptop; age prompts for a passphrase
#  -> ~/poac-secrets/poac-secrets-<UTC stamp>.tar.age
deploy/restore-secrets.sh ~/poac-secrets/poac-secrets-….tar.age          # list contents
deploy/restore-secrets.sh ~/poac-secrets/poac-secrets-….tar.age --to root@NEWHOST
```

The backup runs on your machine and streams an encrypted bundle over SSH;
plaintext exists only in a mode-700 temp dir on the server (which already
holds these files), removed on exit. The corpus is copied with SQLite's
online backup, so it is consistent even while the verifier is serving. The
passphrase is the real secret: put it in your password manager, never
beside the bundle. `-r age1…` encrypts to an age public key instead
(useful for automation; the matching identity then needs the same care).

Restore onto a fresh host after `bootstrap-host.sh`: it stops the verifier,
installs `.env`, copies the data files into the `poac-data` volume (moving
any existing ones aside as `*.bak-<stamp>`), and starts the verifier. Take
a bundle after every corpus change and after any `.env` edit.

## State

Sessions and verify nonces are in-memory by default (single replica). For
multiple replicas use the SQLite-backed stores (`docs/persistence.md`).

## Challenge corpus

Without `--corpus-db` (`POAC_CORPUS_DB`) every round comes from the public
template generators (limitation L2). Build a corpus with `poac-corpus`,
mount it on a writable volume (every draw updates exposure counters, so
the read-only root will not do) and point the verifier at it; see
`docs/corpus.md`.
