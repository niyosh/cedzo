#!/usr/bin/env bash
# ==========================================================================
# 00-setup.sh  -  Verify (and optionally install) the tooling the kit uses.
#
# Mode-aware: the internal and external recon chains use different tools, so
# the inventory follows KIT_MODE (set by run.sh; defaults to internal here).
#   KIT_MODE=external ./00-setup.sh   # check the external attack-surface tools
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh

phase "Tool inventory (${KIT_MODE} mode)"

# Tool list comes from the single source of truth (lib/tools.sh, via kit_tools)
# so 00-setup and the prep-phase checks can never drift. Entries are
# "bin:apt:hint:flag" — see lib/tools.sh.
mapfile -t TOOLS < <(kit_tools)

MISSING=()
for entry in "${TOOLS[@]}"; do
  [[ -n "$entry" ]] || continue
  IFS=':' read -r bin apt hint flag <<<"$entry"
  if have "$bin"; then ok "$bin"; else warn "MISSING: $bin${hint:+   ($hint)}"; MISSING+=("$entry"); fi
done

# httpx handled separately: the binary name clashes with the python httpx CLI,
# so resolve the ProjectDiscovery build via httpx_bin (prefers httpx-toolkit).
if httpx_bin >/dev/null 2>&1; then
  ok "$(httpx_bin) (ProjectDiscovery httpx)"
else
  warn "MISSING: ProjectDiscovery httpx   (install httpx-toolkit — the python 'httpx' CLI will NOT work)"
  MISSING+=("httpx-toolkit:httpx-toolkit:")
fi

# netexec family handled separately (internal only)
if [[ "$KIT_MODE" != "external" ]]; then
  if nxc_bin >/dev/null; then ok "$(nxc_bin) (netexec/cme)"; else warn "MISSING: netexec/crackmapexec"; fi
fi

if [[ ${#MISSING[@]} -eq 0 ]]; then ok "All tools present."; exit 0; fi

echo
warn "${#MISSING[@]} tool(s) missing — modules that need them degrade gracefully."

# Installing is OPT-IN and must never block a non-interactive run (piped, CI,
# IDE terminal). Drive it with AUTO_INSTALL=1, or answer the prompt 'y' when
# run from a real terminal. The `|| ans=...` keeps `set -e` from killing us if
# read hits EOF (closed stdin), which would otherwise abort before the check.
ans="${AUTO_INSTALL:-}"
if [[ -z "$ans" ]]; then
  if [[ -t 0 ]]; then
    read -rp "Attempt to install missing tools via apt/pipx? [y/N] " ans || ans=""
  else
    log "Non-interactive shell — not installing. Re-run with AUTO_INSTALL=1 (or from a terminal) to install."
    exit 0
  fi
fi
[[ "$ans" =~ ^([Yy]|yes|1)$ ]] || { warn "Skipping install. Some modules will degrade gracefully."; exit 0; }

sudo apt-get update -qq || true
for entry in "${MISSING[@]}"; do
  IFS=':' read -r bin apt hint flag <<<"$entry"
  log "Installing $bin ..."
  if [[ -z "$apt" ]]; then
    warn "$bin has no apt package — install manually: ${hint:-see project docs}"
    continue
  fi
  sudo apt-get install -y "$apt" 2>/dev/null \
    || { [[ -n "$hint" ]] && pipx install "$hint" 2>/dev/null; } \
    || warn "Could not auto-install $bin — install manually${hint:+: $hint}."
done
if [[ "$KIT_MODE" != "external" ]]; then
  have "$(nxc_bin 2>/dev/null)" || pipx install netexec 2>/dev/null || warn "Install netexec manually: pipx install netexec"
fi
ok "Setup pass complete."
