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

Images are built in GitHub Actions (`.github/workflows/image.yml`) and
published as `ghcr.io/42-bytes/poac-verifier:main` and
`ghcr.io/42-bytes/poac-caddy:main`; `docker compose pull` on a node avoids
compiling Lean there. `docker compose build` still works for local builds.

### TLS via DNS-01

The proxy is Caddy with the `route53` DNS module (`deploy/caddy/`). It gets
its certificate by ACME DNS-01 against the Route 53 hosted zone of
`POAC_PUBLIC_HOST`, using the `poac-dns01` IAM user, which may only write
TXT records in that one zone. The Caddy container receives only those DNS
credentials; the KMS signer credentials go only to the verifier. DNS-01
means a node can hold a valid certificate without receiving traffic, which
is what makes the passive node below usable the moment DNS flips.

## Two nodes: active-passive failover

Hetzner (Helsinki) is the primary; an AWS Lightsail instance (Stockholm,
same region as the KMS keys) is the passive secondary. Both sign with the
same KMS keys, so both publish the same JWKS and receipts verify regardless
of which node issued them. Sessions are per-node (SQLite); a session in
flight during a flip is lost and the agent simply starts a new one. Traffic
is not shared between nodes — the point is availability, not capacity.

DNS: only `poac.42bytes.eu` is delegated to a Route 53 hosted zone (NS
records at the parent, which stays on Cloudflare). Route 53 failover
records point the name at the primary while its health check (HTTPS by IP,
SNI and Host set to the public name, path `/.well-known/jwks.json`, 30 s
interval, 2 failures) passes, and at the secondary otherwise. TTL 60 s, so
a flip propagates in roughly 1–2 minutes. `a.` and `b.` sub-names resolve
directly to each node for drills. Cloudflare's proxy is deliberately not
used: its bot protection would challenge the agents the verifier exists to
serve.

Setup, once, with an admin AWS credential:

```bash
PRIMARY_IP=37.27.146.243 deploy/aws-failover-setup.sh   # Lightsail, zone, health checks, records, dns01 user
```

It prints the `POAC_DNS_*` values for `.env` (once) and the four NS records
to add at the parent. Then on the secondary:

```bash
deploy/bootstrap-host.sh                         # as root (sudo -i on Lightsail)
deploy/restore-secrets.sh ~/poac-secrets/<bundle>.tar.age --to ubuntu@<ip>   # same .env, corpus, trials log
# append POAC_DNS_* and POAC_LEAN_MAX_MEMORY_MB=512 to /opt/poac/.env on a 1 GB box
docker compose pull && docker compose up -d
```

Nightly from the primary, `deploy/sync-secondary.sh ubuntu@<ip>` copies a
consistent corpus snapshot (exposure counters) and the human-trials log so
the secondary does not re-serve items the primary has already retired.

Drill: `docker compose stop verifier` on the primary; within ~2 minutes
`dig +short poac.42bytes.eu` returns the secondary's IP and an agent can
earn and verify a receipt; `docker compose start verifier` flips it back.

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

## Package integrity

Source lives at `github.com/42-bytes/poac`. CI (`.github/workflows/ci.yml`)
runs the tests on 3.12/3.13, builds the wheel and sdist, and scans the
full git history with gitleaks (`.gitleaks.toml` allowlists two known
false positives). Releases (`release.yml`) fire on a `v*` tag and publish
to PyPI through Trusted Publishing — GitHub's OIDC token is exchanged for
a short-lived upload token, so no PyPI credential exists anywhere — with
Sigstore attestations attached (PEP 740). The GitHub environment `pypi`
gates the publish job; add required reviewers there if more than one
person can tag.

Release: bump `version` in `pyproject.toml`, commit, `git tag vX.Y.Z &&
git push --tags`. Consumers verify provenance with `pypi-attestations`.

## State

Sessions and verify nonces are in-memory by default (single replica). For
multiple replicas use the SQLite-backed stores (`docs/persistence.md`).

## Challenge corpus

Without `--corpus-db` (`POAC_CORPUS_DB`) every round comes from the public
template generators (limitation L2). Build a corpus with `poac-corpus`,
mount it on a writable volume (every draw updates exposure counters, so
the read-only root will not do) and point the verifier at it; see
`docs/corpus.md`.
