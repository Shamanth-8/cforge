#!/usr/bin/env bash
# setup.sh — reset targets and stage logs.
#
#   ./setup.sh                 # (re)stage targets and recorders for a fresh run
#   ./setup.sh --run <run_id>  # validate an archived run and print its path for
#                              #   ThreatLoop to read from
#   ./setup.sh --list          # list archived runs
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/config.sh"
source "$LIB_DIR/common.sh"

MODE="reset"
RUN_ID=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --run)  MODE="stage"; RUN_ID="$2"; shift 2 ;;
    --list) MODE="list"; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

case "$MODE" in
  reset)
    log "resetting targets and staging recorders"
    bash "$ATTACKER_ROOT/targets/juice_shop/launch.sh" || true
    bash "$ATTACKER_ROOT/targets/dvwa/launch.sh" || true
    bash "$ATTACKER_ROOT/targets/ssh_host/setup_accounts.sh" || true
    mkdir -p "$RUNS_DIR"
    log "ready. Run ./run_all.sh to execute the 11 test cases."
    ;;

  list)
    log "archived runs in $RUNS_DIR:"
    if [[ -d "$RUNS_DIR" ]]; then
      find "$RUNS_DIR" -maxdepth 1 -mindepth 1 -type d -printf '  %f\n' | sort
    else
      echo "  (none)"
    fi
    ;;

  stage)
    RUN_DIR="$RUNS_DIR/$RUN_ID"
    [[ -d "$RUN_DIR" ]] || die "run not found: $RUN_DIR"
    missing=0
    for f in auth.log network.jsonl proxy.json manifest.json; do
      if [[ -s "$RUN_DIR/$f" ]]; then
        log "ok: $f"
      else
        warn "missing or empty: $f"
        missing=1
      fi
    done
    [[ "$missing" == "0" ]] || die "run $RUN_ID is incomplete"
    # Validate manifest + proxy.json parse.
    "$PYTHON" -c "import json;json.load(open('$RUN_DIR/manifest.json'));json.load(open('$RUN_DIR/proxy.json'))" \
      || die "run $RUN_ID has invalid JSON"
    log "run $RUN_ID is valid and staged."
    echo "$RUN_DIR"
    ;;
esac
