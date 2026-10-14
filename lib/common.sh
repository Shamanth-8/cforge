#!/usr/bin/env bash
# Common helpers for ATTACKER attack scripts. Source this after config.sh.
set -euo pipefail

if [[ -z "${ATTACKER_ROOT:-}" ]]; then
  # shellcheck source=/dev/null
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/config.sh"
fi

log()  { printf '[attacker] %s\n' "$*" >&2; }
warn() { printf '[attacker][warn] %s\n' "$*" >&2; }
die()  { printf '[attacker][error] %s\n' "$*" >&2; exit 1; }

# RUN_DIR is passed to each attack script as $1. Resolve or create it.
resolve_run_dir() {
  local run_arg="${1:-}"
  if [[ -z "$run_arg" ]]; then
    # Standalone invocation: spin up a one-off run so a single TC can be rerun.
    local rid
    rid="$("$PYTHON" "$LIB_DIR/run.py" init --root "$RUNS_DIR")"
    RUN_DIR="$RUNS_DIR/$rid"
    log "standalone run: $RUN_DIR"
  elif [[ -d "$run_arg" ]]; then
    RUN_DIR="$run_arg"
  elif [[ -d "$RUNS_DIR/$run_arg" ]]; then
    RUN_DIR="$RUNS_DIR/$run_arg"
  else
    die "run directory not found: $run_arg"
  fi
  export RUN_DIR
}

# Refuse to launch real tools at anything outside the private lab ranges.
assert_lab_target() {
  local ip="$1"
  [[ "$ALLOW_NONLAB" == "1" ]] && return 0
  case "$ip" in
    10.*|192.168.*|127.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
    *) die "refusing real-tool execution against non-lab target '$ip' (set ALLOW_NONLAB=1 to override)" ;;
  esac
}

# True only when real-tool execution is enabled AND the binary exists.
have_tool() { command -v "$1" >/dev/null 2>&1; }
real_tools_enabled() { [[ "${EXEC_REAL_TOOLS:-0}" == "1" ]]; }

# Emit the normalized ground-truth logs + manifest marker for a test case.
generate_logs() {
  local tc_id="$1"
  "$PYTHON" "$LIB_DIR/run.py" generate --run-dir "$RUN_DIR" "$tc_id"
}

# Load catalog values for a test case into TC_* shell variables.
load_tc() {
  eval "$("$PYTHON" "$LIB_DIR/run.py" catalog "$1")"
}
