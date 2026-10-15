#!/usr/bin/env bash
# Keep the passive node's non-secret state close to the primary's: a
# consistent snapshot of the corpus (exposure/retirement counters) and the
# human-trial log. Run on the PRIMARY (cron, nightly). Secrets (.env, keys)
# are NOT synced — they come from the age bundle via restore-secrets.sh.
#
#   deploy/sync-secondary.sh ubuntu@<secondary ip>
set -euo pipefail
TARGET="${1:?usage: sync-secondary.sh user@secondary}"
SSH_KEY="${POAC_SSH_KEY:-$HOME/.ssh/poac_sync}"
cd /opt/poac
W=$(mktemp -d); chmod 700 "$W"; trap 'rm -rf "$W"' EXIT
docker compose exec -T verifier sh -ec '
  python - <<PY
import os, sqlite3
if os.path.exists("/data/corpus.sqlite"):
    src = sqlite3.connect("/data/corpus.sqlite"); dst = sqlite3.connect("/tmp/corpus-sync.sqlite")
    src.backup(dst); dst.close(); src.close()
PY
  tar -C / -cf - tmp/corpus-sync.sqlite data/human-trials.jsonl data/previous-keys.json 2>/dev/null; rm -f /tmp/corpus-sync.sqlite' \
  | tar -C "$W" -xf -
# into the secondary's volume, via its own verifier container (same uid), without stopping it
tar -C "$W" -cf - . | ssh -i "$SSH_KEY" "$TARGET" 'cd /opt/poac && T=$(mktemp -d) && tar -C "$T" -xf - && \
  sudo docker run --rm -v poac_poac-data:/data -v "$T:/src:ro" alpine sh -ec "
    [ -f /src/tmp/corpus-sync.sqlite ] && cp /src/tmp/corpus-sync.sqlite /data/corpus.sqlite.sync && mv /data/corpus.sqlite.sync /data/corpus.sqlite && rm -f /data/corpus.sqlite-wal /data/corpus.sqlite-shm
    [ -f /src/data/human-trials.jsonl ] && cp /src/data/human-trials.jsonl /data/human-trials.jsonl
    [ -f /src/data/previous-keys.json ] && cp /src/data/previous-keys.json /data/previous-keys.json
    chown 10001:10001 /data/corpus.sqlite /data/human-trials.jsonl /data/previous-keys.json 2>/dev/null || true" && rm -rf "$T"'
echo "synced corpus snapshot + trials log to $TARGET at $(date -u +%FT%TZ)"
