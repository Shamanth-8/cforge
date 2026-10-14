#!/usr/bin/env bash
# TC-05  T1048  Data exfiltration  (Caldera -> outbound from lab host)
# Large outbound data transfer from a host above its baseline.
# Expected: large_outbound_data_transfer.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"

resolve_run_dir "${1:-}"
load_tc TC-05
log "TC-05 data exfiltration (volume) from ${TC_SRC}"

if real_tools_enabled; then
  # Caldera drives the exfil ability from the compromised lab host. Wire the
  # Caldera operation here when a Caldera server + agent are provisioned.
  if have_tool caldera 2>/dev/null; then
    warn "Caldera CLI hook not wired; emitting normalized logs only"
  else
    warn "Caldera not available; emitting normalized logs only"
  fi
fi

generate_logs TC-05
