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

# tool : apt-package : install hint (pipx package, or a go/manual hint; blank = apt/kali default)
if [[ "$KIT_MODE" == "external" ]]; then
  # External attack-surface recon — only tools the x0*-phases actually invoke.
  TOOLS=(
    "nmap:nmap:"                 # x03 port/service scan, x07 TLS
    "whois:whois:"              # x02 WHOIS/ASN
    "dig:dnsutils:"             # x02 DNS records
    "curl:curl:"                # x04 exposures, AI layer
    "jq:jq:"                    # AI layer (lib/ai-ext.sh)
    "subfinder:subfinder:"      # x02 subdomain enum
    "amass:amass:"              # x02 subdomain enum
    "dnsx:dnsx:"                # x02 resolution
    "nuclei:nuclei:"            # x04/x07 vuln scan
    "whatweb:whatweb:"          # x04 fingerprint
    "feroxbuster:feroxbuster:"  # x04 content discovery
    "katana:katana:"            # x04 crawl
    "gowitness:gowitness:"      # x04 screenshots
    "ffuf:ffuf:"                # x04 vhost discovery
    "wpscan:wpscan:"            # x04 WordPress
    "testssl.sh:testssl.sh:"    # x07 TLS/SSL audit
    "onesixtyone:onesixtyone:"  # x05/x07 SNMP
    "showmount:nfs-common:"     # x05 NFS exposure
    "subzy::go install github.com/LukaSikic/subzy@latest"   # x06 takeover
    "subjack::go install github.com/haccer/subjack@latest"  # x06 takeover
    "noseyparker:noseyparker:"  # x08 secret scan
    "glow:glow:"                # markdown report rendering
    "python3:python3:"          # reporting/* + xlsx
    "zip:zip:"                  # x09 run archive
    "tar:tar:"                  # x09 archive fallback
  )
else
  # Internal network recon — only tools the 0*-phases actually invoke.
  TOOLS=(
    "nmap:nmap:"                 # 02 port/service scan, 07 TLS/vuln NSE
    "masscan:masscan:"          # 02 fast TCP discovery (optional)
    "enum4linux-ng:enum4linux-ng:"  # 03 SMB/AD enumeration
    "ldapsearch:ldap-utils:"    # 03 DC LDAP rootDSE / anon bind
    "dnsrecon:dnsrecon:"        # 03 DNS std/SRV/AXFR
    "nuclei:nuclei:"            # 04/07 vuln scan
    "whatweb:whatweb:"          # 04 fingerprint
    "feroxbuster:feroxbuster:"  # 04 content discovery
    "katana:katana:"            # 04 crawl
    "gowitness:gowitness:"      # 04 screenshots
    "ffuf:ffuf:"                # 04 vhost discovery
    "wpscan:wpscan:"            # 04 WordPress
    "ntlmrecon:ntlmrecon:"      # 04 NTLM endpoint recon
    "shortscan:shortscan:"      # 04 IIS 8.3 short-name disclosure
    "cmseek:cmseek:"            # 04 CMS enum (optional, WEB_CMS=true)
    "curl:curl:"                # 04 exposures, AI layer
    "jq:jq:"                    # AI layer (lib/ai.sh)
    "kerbrute:kerbrute:"        # 06 user enum / AS-REP
    "bloodhound-python:bloodhound:bloodhound"      # 06 BloodHound collection
    "GetUserSPNs.py:python3-impacket:impacket"     # 06 Kerberoast/AS-REP (impacket)
    "certipy:python3-certipy:certipy-ad"           # 06 ADCS enumeration
    "showmount:nfs-common:"     # 03 NFS exports
    "dig:dnsutils:"             # 03 DNS lookups
    "snmpwalk:snmp:"            # 07 SNMP walk
    "onesixtyone:onesixtyone:"  # 07 SNMP community discovery
    "rdpscan:rdpscan:"          # 07 BlueKeep check
    "noseyparker:noseyparker:"  # 08 secret scan
    "glow:glow:"                # markdown report rendering
    "python3:python3:"          # reporting/* + xlsx
    "zip:zip:"                  # 09 run archive
    "tar:tar:"                  # 09 archive fallback
  )
fi

MISSING=()
for entry in "${TOOLS[@]}"; do
  IFS=':' read -r bin apt hint <<<"$entry"
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
  IFS=':' read -r bin apt hint <<<"$entry"
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
