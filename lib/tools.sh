#!/usr/bin/env bash
# ==========================================================================
# lib/tools.sh  -  SINGLE SOURCE OF TRUTH for the kit's external tool deps.
#
# Consumed by 00-setup.sh (inventory + install) and the prep phases
# (01-prep.sh / x01-prep.sh) for their preflight checks — so the tool list
# lives in exactly one place and the two can never drift apart.
#
#   kit_tools [mode]   ->  one "bin:apt:hint:flag" entry per line for <mode>
#                          (default $KIT_MODE; falls back to internal).
#
#     bin   - command checked with `have`
#     apt   - apt package name (blank = no apt package; install via hint)
#     hint  - pipx package or go/manual install hint (blank = apt default)
#     flag  - "req" if the kit cannot run without it; blank = optional
#
# Tools resolved by name-tolerant helpers are handled SEPARATELY by the
# consumers (not listed here): ProjectDiscovery httpx (httpx_bin) and
# NetExec/CrackMapExec (nxc_bin, internal only).
# ==========================================================================

kit_tools() {
  local mode="${1:-${KIT_MODE:-internal}}"
  if [[ "$mode" == "external" ]]; then
    cat <<'EOF'
nmap:nmap::req
whois:whois:
dig:dnsutils:
curl:curl:
jq:jq:
subfinder:subfinder:
amass:amass:
dnsx:dnsx:
nuclei:nuclei:
whatweb:whatweb:
feroxbuster:feroxbuster:
katana:katana:
gowitness:gowitness:
ffuf:ffuf:
wpscan:wpscan:
testssl.sh:testssl.sh:
onesixtyone:onesixtyone:
showmount:nfs-common:
subzy::go install github.com/LukaSikic/subzy@latest
subjack::go install github.com/haccer/subjack@latest
noseyparker:noseyparker:
glow:glow:
python3:python3:
zip:zip:
tar:tar:
EOF
  else
    cat <<'EOF'
nmap:nmap::req
masscan:masscan:
enum4linux-ng:enum4linux-ng:
ldapsearch:ldap-utils:
dnsrecon:dnsrecon:
nuclei:nuclei:
whatweb:whatweb:
feroxbuster:feroxbuster:
katana:katana:
gowitness:gowitness:
ffuf:ffuf:
wpscan:wpscan:
ntlmrecon:ntlmrecon:
shortscan:shortscan:
cmseek:cmseek:
curl:curl:
jq:jq:
kerbrute:kerbrute:
bloodhound-python:bloodhound:bloodhound
GetUserSPNs.py:python3-impacket:impacket
certipy:python3-certipy:certipy-ad
showmount:nfs-common:
dig:dnsutils:
snmpwalk:snmp:
onesixtyone:onesixtyone:
rdpscan:rdpscan:
noseyparker:noseyparker:
glow:glow:
python3:python3:
zip:zip:
tar:tar:
EOF
  fi
}
