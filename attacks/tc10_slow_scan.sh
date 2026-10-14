#!/usr/bin/env bash
# TC-10  T1046  Slow port scan  (Nmap timing -> lab host)
# Few ports per time window spread over hours to stay under a rate threshold.
# Expected: few_ports_per_window_evades_threshold.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"

resolve_run_dir "${1:-}"
load_tc TC-10
log "TC-10 slow port scan -> ${TC_DST} (spread over ${TC_WINDOW}s in logs)"

if real_tools_enabled; then
  assert_lab_target "$TC_DST"
  if have_tool nmap; then
    log "running Nmap with evasive timing (-T1 paranoid-ish) against lab host"
    nmap -Pn -T1 --scan-delay 2s -p 1-200 "$TC_DST" \
      2>>"$RUN_DIR/_tools.log" >>"$RUN_DIR/_tools.log" || true
  else
    warn "nmap not installed; emitting normalized logs only"
  fi
fi

generate_logs TC-10
