#!/usr/bin/env bash
# Stop the log recorders and archive the run.
#
# The test environment is intentionally NOT recovered: targets are left
# destroyed. Only the recorded logs survive, which is what ThreatLoop reads.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/config.sh"

RUN_DIR="${1:?usage: stop_recorders.sh <run_dir>}"
echo "[recorder] stopping collectors for $RUN_DIR"

# If real collectors were started as background processes with recorded PIDs,
# stop them here. (No-op when the engine-normalized output was used.)
if [[ -f "$RUN_DIR/_recorder.pids" ]]; then
  while read -r pid; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  done < "$RUN_DIR/_recorder.pids"
  rm -f "$RUN_DIR/_recorder.pids"
fi

echo "[recorder] collectors stopped. Targets are left destroyed (by design)."
