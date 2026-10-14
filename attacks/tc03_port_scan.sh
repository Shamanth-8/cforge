#!/usr/bin/env bash
# TC-03  T1046  Port scan  (Nmap -> lab host)
# Many distinct destination ports probed from one source in a short window.
# Expected: many_distinct_ports_from_single_source.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"

resolve_run_dir "${1:-}"
load_tc TC-03
log "TC-03 port scan -> ${TC_DST}"

if real_tools_enabled; then
  assert_lab_target "$TC_DST"
  if have_tool nmap; then
    log "running Nmap fast scan against lab host"
    nmap -Pn -T4 -p 1-1000 "$TC_DST" 2>>"$RUN_DIR/_tools.log" \
      >>"$RUN_DIR/_tools.log" || true
  else
    warn "nmap not installed; emitting normalized logs only"
  fi
fi

generate_logs TC-03
