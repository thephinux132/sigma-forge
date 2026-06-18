#!/usr/bin/env bash
# Pull recent Cowrie honeypot telemetry from the sensor for Sigma-Forge (v2 live data).
# Usage: pull_cowrie.sh [host] [out_path] [lines]
set -uo pipefail
HOST="${1:-pi5security}"
# Default output path is derived from this script's location (repo/data/), so no
# absolute user path is hard-coded into the public source.
OUT="${2:-$(cd "$(dirname "$0")/.." && pwd)/data/cowrie_live.json}"
LINES="${3:-5000}"
mkdir -p "$(dirname "$OUT")"

# Locate the live cowrie json on the sensor (bounded roots = fast).
LOGPATH=$(ssh -o ConnectTimeout=10 "$HOST" \
  'find /srv /opt /home /var/lib /var/log -name cowrie.json -type f 2>/dev/null | head -1')

if [ -z "$LOGPATH" ]; then
  echo "NO_COWRIE_LOG_FOUND on $HOST"
  exit 3
fi
echo "FOUND $LOGPATH on $HOST"

# Concatenate the live json + any rotated siblings (cowrie.json.YYYY-MM-DD),
# oldest-first, then keep the most recent N lines. Maximizes the live window
# when the honeypot is low-volume.
DIR=$(dirname "$LOGPATH")
ssh -o ConnectTimeout=10 "$HOST" \
  "cd '$DIR' && cat \$(ls -1tr cowrie.json* 2>/dev/null) 2>/dev/null | tail -n $LINES" > "$OUT"
COUNT=$(grep -c . "$OUT" 2>/dev/null || echo 0)
echo "WROTE $COUNT lines -> $OUT"
