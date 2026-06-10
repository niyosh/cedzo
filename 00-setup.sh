#!/usr/bin/env bash
# ==========================================================================
# 00-setup.sh  -  Verify (and optionally install) the tooling the kit uses.
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh

phase "Tool inventory"

# tool : apt-package : pipx-install (blank = apt/kali default)
TOOLS=(
  "nmap:nmap:"
  "masscan:masscan:"
  "fping:fping:"
  "arp-scan:arp-scan:"
  "enum4linux-ng:enum4linux-ng:"
  "smbclient:smbclient:"
  "rpcclient:samba-common-bin:"
  "ldapsearch:ldap-utils:"
  "httpx:httpx-toolkit:"
  "nuclei:nuclei:"
  "whatweb:whatweb:"
  "feroxbuster:feroxbuster:"
  "katana:katana:"
  "gowitness:gowitness:"
  "kerbrute:kerbrute:"
  "bloodhound-python:bloodhound:bloodhound"
  "GetUserSPNs.py:python3-impacket:impacket"
  "certipy:python3-certipy:certipy-ad"
  "showmount:nfs-common:"
  "dig:dnsutils:"
  "snmpwalk:snmp:"
  "onesixtyone:onesixtyone:"
  "rdpscan:rdpscan:"
  "wpscan:wpscan:"
  "ffuf:ffuf:"
  "curl:curl:"
  "dnsrecon:dnsrecon:"
  "ntlmrecon:ntlmrecon:"
  "shortscan:shortscan:"
  "noseyparker:noseyparker:"
)

MISSING=()
for entry in "${TOOLS[@]}"; do
  IFS=':' read -r bin apt pipx <<<"$entry"
  if have "$bin"; then ok "$bin"; else warn "MISSING: $bin"; MISSING+=("$entry"); fi
done

# netexec family handled separately
if nxc_bin >/dev/null; then ok "$(nxc_bin) (netexec/cme)"; else warn "MISSING: netexec/crackmapexec"; fi

if [[ ${#MISSING[@]} -eq 0 ]]; then ok "All tools present."; exit 0; fi

echo
read -rp "Attempt to install missing tools via apt/pipx? [y/N] " ans
[[ "$ans" =~ ^[Yy]$ ]] || { warn "Skipping install. Some modules will degrade gracefully."; exit 0; }

sudo apt-get update -qq || true
for entry in "${MISSING[@]}"; do
  IFS=':' read -r bin apt pipx <<<"$entry"
  log "Installing $bin ..."
  sudo apt-get install -y "$apt" 2>/dev/null \
    || { [[ -n "$pipx" ]] && pipx install "$pipx" 2>/dev/null; } \
    || warn "Could not auto-install $bin — install manually."
done
have "$(nxc_bin 2>/dev/null)" || pipx install netexec 2>/dev/null || warn "Install netexec manually: pipx install netexec"
ok "Setup pass complete."
