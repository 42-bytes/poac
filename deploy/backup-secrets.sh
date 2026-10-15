#!/usr/bin/env bash
# Pull the verifier's secrets off the server into ONE age-encrypted bundle on
# this machine. Run from your laptop; nothing is written unencrypted here.
#
#   deploy/backup-secrets.sh                       # passphrase (prompted by age)
#   deploy/backup-secrets.sh -r age1...            # or an age recipient key
#
# Bundle contents (tar.gz inside age):
#   env                      /opt/poac/.env   (server secret, KMS signer creds)
#   data/issuer.jwk          local Ed25519 issuer key (private); absent once retired
#   data/corpus.sqlite       private challenge corpus — consistent SQLite snapshot
#   data/human-trials.jsonl  human-trial log (not secret, but irreplaceable)
#
# Output: ~/poac-secrets/poac-secrets-<UTC stamp>.tar.age (dir chmod 700).
# THE PASSPHRASE IS THE REAL SECRET: keep it in your password manager, not
# next to the bundle. Restore with deploy/restore-secrets.sh.
set -euo pipefail

HOST="${POAC_HOST:-root@37.27.146.243}"
SSH_KEY="${POAC_SSH_KEY:-$HOME/.ssh/poac_hetzner}"
OUT_DIR="${POAC_BACKUP_DIR:-$HOME/poac-secrets}"
RECIPIENT=""
while getopts "r:" opt; do
  case "$opt" in r) RECIPIENT="$OPTARG" ;; *) exit 2 ;; esac
done

command -v age >/dev/null || { echo "age not installed (brew install age)" >&2; exit 1; }
mkdir -p "$OUT_DIR" && chmod 700 "$OUT_DIR"
OUT="$OUT_DIR/poac-secrets-$(date -u +%Y%m%dT%H%MZ).tar.age"

# On the server: snapshot the corpus with SQLite's online backup (WAL-safe)
# inside the verifier container, pull the data files out, add .env, stream a
# tar.gz to stdout. Plaintext exists only in a mode-700 temp dir on the
# server (which already holds these files) and is removed on exit.
# shellcheck disable=SC2016
REMOTE='set -euo pipefail; cd /opt/poac
W=$(mktemp -d); chmod 700 "$W"; trap "rm -rf $W" EXIT
docker compose exec -T verifier sh -ec "
  rm -rf /tmp/bundle && mkdir -p /tmp/bundle/data
  python - <<PY
import os, sqlite3
if os.path.exists(\"/data/corpus.sqlite\"):
    src = sqlite3.connect(\"/data/corpus.sqlite\")
    dst = sqlite3.connect(\"/tmp/bundle/data/corpus.sqlite\")
    src.backup(dst); dst.close(); src.close()
PY
  for f in issuer.jwk human-trials.jsonl; do [ -f /data/\$f ] && cp -p /data/\$f /tmp/bundle/data/ || true; done
  tar -C /tmp/bundle -cf - data; rm -rf /tmp/bundle
" | tar -C "$W" -xf -
cp -p .env "$W/env"
tar -C "$W" -czf - env data'

if [ -n "$RECIPIENT" ]; then
  ssh -i "$SSH_KEY" "$HOST" "$REMOTE" | age -r "$RECIPIENT" -o "$OUT"
else
  echo "age will now ask for a passphrase (twice). Store it in your password manager." >&2
  ssh -i "$SSH_KEY" "$HOST" "$REMOTE" | age -p -o "$OUT"
fi
chmod 600 "$OUT"
echo "wrote $OUT ($(wc -c <"$OUT" | tr -d ' ') bytes)"
echo "verify:  age -d $OUT | tar -tzvf -"
