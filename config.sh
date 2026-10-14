#!/usr/bin/env bash
# Shared configuration for the ATTACKER lab.
# All targets live on an isolated, private lab subnet. ATTACKER is only ever
# pointed at these intentionally vulnerable, disposable test environments.

# Resolve the attacker/ root regardless of where a script is invoked from.
ATTACKER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ATTACKER_ROOT
export LIB_DIR="$ATTACKER_ROOT/lib"
export RUNS_DIR="$ATTACKER_ROOT/runs"

# --- Lab network (private, non-routable; RFC1918) ---------------------------
export LAB_SUBNET="192.168.56.0/24"
export SSH_HOST="192.168.56.10"
export JUICE_SHOP_HOST="192.168.56.20"
export DVWA_HOST="192.168.56.21"
export JUICE_SHOP_PORT="3000"
export DVWA_PORT="80"
export PROMPT_HANDLER_PORT="8080"

# --- Execution flags --------------------------------------------------------
# EXEC_REAL_TOOLS=1 invokes the real open-source tools (Hydra, Nmap, sqlmap,
# Caldera) against the lab targets when they are installed and reachable.
# When 0 (default), the run produces the normalized ground-truth logs only,
# which is all ThreatLoop needs as input. The normalized logs are emitted in
# BOTH modes so a run is always reproducible and parseable.
export EXEC_REAL_TOOLS="${EXEC_REAL_TOOLS:-0}"

# Safety guard: refuse to launch real tools at anything outside the private
# lab ranges unless the operator explicitly overrides it.
export ALLOW_NONLAB="${ALLOW_NONLAB:-0}"

export PYTHON="${PYTHON:-python3}"
