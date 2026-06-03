#!/usr/bin/env bash
# ==========================================================================
# 00-prep.sh  -  Preflight checks + build live_hosts.txt from scope.txt.
#                All IPs in scope are treated as reachable; no ping gating.
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh
require_scope
RUN="${RUN:?RUN not set — launch via run.sh}"

phase "Preflight"

# ---- Sub-task: scope validation ----------------------------------------------
t_validate_scope() {
  log "Validating scope.txt"
  local bad
  bad=$(clean_scope | grep -vE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$' || true)
  if [[ -n "$bad" ]]; then
    err "scope.txt contains non-IP lines (CIDRs are fine; hostnames are not):"
    echo "$bad"
    exit 1
  fi
  ok "Scope entries: $(clean_scope | wc -l)"
}

# ---- Sub-task: tool checks ---------------------------------------------------
t_check_tools() {
  log "Checking required tools"
  local MISSING=() tool
  for tool in nmap sudo; do
    have "$tool" || MISSING+=("$tool")
  done
  if [[ ${#MISSING[@]} -gt 0 ]]; then
    err "Missing required tools: ${MISSING[*]}"
    exit 1
  fi
  for tool in masscan crackmapexec netexec impacket-secretsdump nuclei \
              ldeep impacket-findDelegation; do
    have "$tool" || warn "Optional tool not found: $tool (some phases will skip it)"
  done
  ok "Tool check complete"
}

# ---- Sub-task: build live host list ------------------------------------------
t_build_hosts() {
  log "Building live_hosts.txt from scope.txt"
  clean_scope | sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n > "$RUN/live_hosts.txt"
  ok "$(wc -l < "$RUN/live_hosts.txt") hosts loaded -> $RUN/live_hosts.txt"
  column "$RUN/live_hosts.txt" 2>/dev/null || cat "$RUN/live_hosts.txt"
}

task validate_scope "Validate scope.txt (IP/CIDR syntax)"          t_validate_scope
task check_tools    "Check required + optional tools are installed" t_check_tools
task build_hosts    "Build live_hosts.txt from scope"               t_build_hosts
run_tasks
