#!/usr/bin/env bash
# run_all.sh — execute all 11 ATTACKER test cases in order and archive the run.
#
# Produces runs/<run_id>/ with auth.log, network.jsonl, proxy.json, manifest.json.
# The test environment is intentionally destroyed during the attacks; only the
# archived logs survive, and those are what ThreatLoop reads and defends against.
#
# Usage:
#   ./run_all.sh                 # new run, normalized logs (EXEC_REAL_TOOLS=0)
#   ./run_all.sh --run-id ID     # fix the run id
#   ./run_all.sh --base EPOCH    # fix the base clock (reproducible timestamps)
#   EXEC_REAL_TOOLS=1 ./run_all.sh   # also drive the real tools at live targets
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/config.sh"
source "$LIB_DIR/common.sh"

RUN_ID_ARG=""
BASE_ARG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id) RUN_ID_ARG="$2"; shift 2 ;;
    --base)   BASE_ARG="$2"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

mkdir -p "$RUNS_DIR"
INIT_ARGS=(init --root "$RUNS_DIR")
[[ -n "$RUN_ID_ARG" ]] && INIT_ARGS+=(--run-id "$RUN_ID_ARG")
[[ -n "$BASE_ARG" ]] && INIT_ARGS+=(--base "$BASE_ARG")
RUN_ID="$("$PYTHON" "$LIB_DIR/run.py" "${INIT_ARGS[@]}")"
RUN_DIR="$RUNS_DIR/$RUN_ID"
export RUN_DIR
log "run id: $RUN_ID"
log "run dir: $RUN_DIR"

# 1. Start targets (intentionally vulnerable, disposable).
log "starting test targets..."
bash "$ATTACKER_ROOT/targets/juice_shop/launch.sh" || true
bash "$ATTACKER_ROOT/targets/dvwa/launch.sh" || true
bash "$ATTACKER_ROOT/targets/ssh_host/setup_accounts.sh" || true

# 2. Start recorders.
bash "$ATTACKER_ROOT/recorders/start_recorders.sh" "$RUN_DIR" || true

# 3. Benign background traffic (no manifest entry; ThreatLoop's benign baseline).
log "generating benign background traffic..."
"$PYTHON" "$LIB_DIR/run.py" benign --run-dir "$RUN_DIR"

# 4. Attacks, in order. Each is independently rerunnable with the run dir.
ATTACKS=(
  "attacks/tc01_ssh_bruteforce.sh"
  "attacks/tc02_password_spray.sh"
  "attacks/tc03_port_scan.sh"
  "attacks/tc04_sqli_classic.sh"
  "attacks/tc05_exfil_volume.sh"
  "attacks/tc06_impossible_travel.sh"
  "attacks/tc07_prompt_injection.py"
  "attacks/tc08_sqli_encoded.sh"
  "attacks/tc09_prompt_injection_paraphrased.py"
  "attacks/tc10_slow_scan.sh"
  "attacks/tc11_slow_exfil.sh"
)

for a in "${ATTACKS[@]}"; do
  path="$ATTACKER_ROOT/$a"
  log "running $a"
  if [[ "$a" == *.py ]]; then
    "$PYTHON" "$path" "$RUN_DIR"
  else
    bash "$path" "$RUN_DIR"
  fi
done

# 5. Stop recorders. Targets are left destroyed on purpose.
bash "$ATTACKER_ROOT/recorders/stop_recorders.sh" "$RUN_DIR" || true

# 6. Finalize: assemble the log contract + manifest ground truth.
log "finalizing run..."
"$PYTHON" "$LIB_DIR/run.py" finalize --run-dir "$RUN_DIR"

log "done. archived run: $RUN_DIR"
log "  auth.log       $(wc -l < "$RUN_DIR/auth.log" 2>/dev/null || echo 0) lines"
log "  network.jsonl  $(wc -l < "$RUN_DIR/network.jsonl" 2>/dev/null || echo 0) lines"
log "  proxy.json     $("$PYTHON" -c "import json;print(len(json.load(open('$RUN_DIR/proxy.json'))))" 2>/dev/null || echo 0) records"
log "  manifest.json  $("$PYTHON" -c "import json;print(len(json.load(open('$RUN_DIR/manifest.json'))['test_cases']))" 2>/dev/null || echo 0) test cases"
