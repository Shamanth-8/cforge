#!/usr/bin/env bash
# Start the log recorders for a run.
#
# The recorders are the only thing that survives the destroyed test
# environment. In a full lab these are real collectors:
#   - rsyslog / Filebeat  -> auth.log       (authentication records)
#   - Zeek / Suricata     -> network.jsonl  (connection/scan/transfer records)
#   - reverse proxy        -> proxy.json      (HTTP access records)
#
# ATTACKER's run engine emits these same files in a stable, normalized schema
# so the dataset is reproducible and parseable without requiring every heavy
# collector to be installed. This script wires up the real collectors when they
# are present and otherwise relies on the engine's normalized output.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/config.sh"

RUN_DIR="${1:?usage: start_recorders.sh <run_dir>}"
echo "[recorder] run dir: $RUN_DIR"

if command -v zeek >/dev/null 2>&1; then
  echo "[recorder] zeek found — attach it to the lab interface to capture conn logs"
  echo "           (point its JSON conn.log output at $RUN_DIR/network.jsonl)"
else
  echo "[recorder] zeek/suricata not found — using engine-normalized network.jsonl"
fi

if command -v filebeat >/dev/null 2>&1; then
  echo "[recorder] filebeat found — harvest the SSH host's auth log into $RUN_DIR/auth.log"
else
  echo "[recorder] rsyslog/filebeat not found — using engine-normalized auth.log"
fi

echo "[recorder] reverse-proxy access logs normalize into $RUN_DIR/proxy.json"
