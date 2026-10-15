#!/usr/bin/env bash
# Inspect or restore a bundle made by deploy/backup-secrets.sh.
#
#   deploy/restore-secrets.sh BUNDLE.tar.age                 # list contents only
#   deploy/restore-secrets.sh BUNDLE.tar.age --to HOST       # restore onto a host
#   deploy/restore-secrets.sh BUNDLE.tar.age --to HOST -i KEYFILE   # age identity instead of passphrase
#
# Restoring writes /opt/poac/.env and the data files into the poac-data
# volume (the verifier is stopped first and started after). Existing files
# on the host are moved aside with a .bak-<stamp> suffix, never overwritten.
# The target host must already have docker + /opt/poac from bootstrap-host.sh.
set -euo pipefail

BUNDLE="${1:?usage: restore-secrets.sh BUNDLE.tar.age [--to HOST] [-i IDENTITY]}"; shift
HOST=""; IDENTITY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --to) HOST="$2"; shift 2 ;;
    -i) IDENTITY="$2"; shift 2 ;;
    *) echo "unknown arg $1" >&2; exit 2 ;;
  esac
done
SSH_KEY="${POAC_SSH_KEY:-$HOME/.ssh/poac_hetzner}"

decrypt() {
  if [ -n "$IDENTITY" ]; then age -d -i "$IDENTITY" "$BUNDLE"; else age -d "$BUNDLE"; fi
}

if [ -z "$HOST" ]; then
  decrypt | tar -tzvf -
  exit 0
fi

echo "restoring $BUNDLE -> $HOST (verifier will restart)" >&2
# shellcheck disable=SC2016
REMOTE='set -euo pipefail; cd /opt/poac
S=$(date -u +%Y%m%dT%H%MZ); W=$(mktemp -d); chmod 700 "$W"; trap "rm -rf $W" EXIT
tar -C "$W" -xzf -
docker compose stop verifier >/dev/null
[ -f .env ] && mv .env ".env.bak-$S"
install -m 600 "$W/env" .env
docker run --rm -i -v poac_poac-data:/data -v "$W/data:/src:ro" alpine sh -ec "
  for f in /src/*; do b=\$(basename \$f); [ -e /data/\$b ] && mv /data/\$b /data/\$b.bak-$S; cp -p \$f /data/\$b; chown 10001:10001 /data/\$b; done
  rm -f /data/corpus.sqlite-wal /data/corpus.sqlite-shm"
docker compose up -d verifier >/dev/null
echo "restored; previous files kept as *.bak-$S"'
decrypt | ssh -i "$SSH_KEY" "$HOST" "$REMOTE"
