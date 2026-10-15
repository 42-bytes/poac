# Persistence and multi-replica deployment

By default `poac-verifier` keeps all state in memory: sessions, verify
nonces and the rate limiter live in the process, the issuer key and the
server secret are generated at start-up. That is correct for one replica and
loses nothing important on restart except in-flight sessions (agents simply
start a new one).

To run more than one replica, three things must be shared:

| What | Why | How |
|------|-----|-----|
| Session + nonce state | a round issued by A may be answered on B; a verify nonce issued by A may be presented on B | `--state-db /path/state.sqlite3` (or `POAC_STATE_DB`) |
| Server secret | the HMAC round chain must verify on any replica | `POAC_SERVER_SECRET=<hex, >= 64 chars>` |
| Issuer key | receipts must carry one `kid`/public key per issuer URL | `--issuer-key-file /path/issuer.jwk` (created on first run, mode 0600) |

`--state-db` refuses to start without the other two, because a half-shared
deployment fails in non-obvious ways (chain mismatches look like protocol
violations by the agent).

```sh
export POAC_SERVER_SECRET=$(openssl rand -hex 32)
poac-verifier --state-db /var/lib/poac/state.sqlite3 \
              --issuer-key-file /var/lib/poac/issuer.jwk \
              --base-url https://poac.example
```

## Guarantees

* Every session mutation runs inside `BEGIN IMMEDIATE … COMMIT`, so two
  replicas cannot both accept the same round (`tests/test_persistence.py::
  test_replay_on_other_replica_is_rejected`).
* The kernel (`proof`) round sets `validating=True` inside the transaction,
  then runs Lean *outside* it. Another replica that receives a resubmission
  meanwhile answers "round is being validated"; the session is voided if the
  kernel crashes (`test_kernel_round_validating_flag_is_shared`).
* Verify nonces are claimed with a single `UPDATE … WHERE used = 0`
  statement, so exactly one replica wins (`test_sqlite_nonce_store_shared`).
* Expired sessions are swept on every `create_session`; expired nonces on
  every `issue`. Nothing grows unbounded.

## Clock

The shared orchestrator uses `time.time()` instead of the monotonic clock,
because deadlines are compared across hosts. Replicas must run NTP; skew
directly adds to or subtracts from the agent's round deadline. Keep skew
well under the smallest round deadline (C0: see `sessions/config.py`).

## Rotation

Issuer keys rotate without a verification gap: the retired public key is
written to `previous-keys.json` with a `retire_at` *before* the new key is
activated, and `jwks()` publishes it until then. Replicas share the data
volume, so one `poac-keys` run covers all of them; restart each replica
afterwards. Procedure and commands: `deployment.md` → "Rotation".

## Scope

SQLite with WAL is adequate for a handful of replicas on one host or a
shared volume. It is a single-writer store: under heavy write contention
`busy_timeout` (5 s) is the ceiling before a 503. Swapping in Postgres or
Redis is a matter of implementing `SessionStore` (`sessions/store.py`) and
`NonceStore` (`api/nonces.py`); the orchestrator never touches the backend
directly.

The in-process rate limiter is intentionally **not** shared: it is a
per-replica nuisance limit, and the real limits belong in the proxy.
