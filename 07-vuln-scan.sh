#!/usr/bin/env bash
# ==========================================================================
# 07-vuln-scan.sh  -  Detection of high-impact infra vulns (no exploitation).
# Flags MS17-010, SMBGhost, Zerologon, PrintNightmare, PetitPotam, signing,
# weak SSL/TLS, etc. These are CHECKS — verify manually before exploiting.
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh
RUN="${RUN:?RUN not set}"
OUT="$RUN/07-vuln"; mkdir -p "$OUT"; LOG="$OUT/vuln.log"
LIVE="$RUN/live_hosts.txt"; SMB="$RUN/hosts_smb.txt"; DC="$RUN/hosts_dc.txt"
RDP="$RUN/hosts_rdp.txt"
NXC=$(nxc_bin) || NXC=""

phase "Vulnerability Detection (non-exploitative)"

# ---- SMB vulns via NSE ----------------------------------------------------
if [[ -s "$SMB" ]]; then
  log "SMB vuln NSE (MS17-010 EternalBlue, SMBGhost, etc.)"
  run "$LOG" sudo nmap -Pn -p445 \
    --script "smb-vuln-ms17-010,smb-vuln-cve-2017-7494,smb-vuln-ms08-067,smb-protocols,smb2-security-mode" \
    -iL "$SMB" -oA "$OUT/smb_vuln" 2>/dev/null || true
  grep -iE 'VULNERABLE|State:' "$OUT/smb_vuln.nmap" 2>/dev/null | tee "$OUT/smb_vuln_summary.txt" || true
fi

# ---- netexec built-in vuln modules ---------------------------------------
if [[ -n "$NXC" && -s "$SMB" ]]; then
  for mod in zerologon petitpotam printnightmare nopac ms17-010 spooler webdav; do
    log "nxc module: $mod"
    run "$LOG" "$NXC" smb "$SMB" -u '' -p '' -M "$mod" 2>/dev/null || true
  done | grep -iE 'VULNERABLE|enabled|True' | tee "$OUT/nxc_vuln_summary.txt" || true
fi

# ---- DC-specific: Zerologon (safe check) ----------------------------------
if [[ -s "$DC" && -n "$NXC" ]]; then
  log "Zerologon safe-check against DCs"
  run "$LOG" "$NXC" smb "$DC" -u '' -p '' -M zerologon 2>/dev/null || true
fi

# ---- SMBGhost CVE-2020-0796 (SMBv3.1.1 compression) -----------------------
if [[ -s "$SMB" ]]; then
  log "SMBGhost (CVE-2020-0796) detection"
  run "$LOG" sudo nmap -Pn -p445 --script smb-vuln-cve-2020-0796 \
    -iL "$SMB" -oN "$OUT/smbghost.txt" 2>/dev/null || true
  grep -iE 'VULNERABLE|cve-2020-0796' "$OUT/smbghost.txt" 2>/dev/null \
    | tee -a "$OUT/smb_vuln_summary.txt" || true
fi

# ---- BlueKeep CVE-2019-0708 (RDP) — safe check via rdpscan ----------------
if [[ -s "$RDP" ]] && have rdpscan; then
  log "BlueKeep (CVE-2019-0708) safe check on RDP hosts"
  while read -r ip; do
    [[ -n "$ip" ]] || continue
    rdpscan "$ip" 2>/dev/null | tee -a "$OUT/bluekeep.txt" || true
  done < "$RDP"
  grep -i 'VULNERABLE' "$OUT/bluekeep.txt" 2>/dev/null && warn "BlueKeep candidates -> $OUT/bluekeep.txt" || true
fi

# ---- Targeted nuclei sweep for high-impact CVEs ---------------------------
# Log4Shell / ProxyShell / ProxyLogon / Spring4Shell against discovered web.
if [[ -s "$RUN/web_urls.txt" ]] && have nuclei; then
  log "nuclei targeted CVE sweep (log4j, proxyshell, proxylogon, spring4shell)"
  run "$LOG" nuclei -l "$RUN/web_urls.txt" \
    -tags log4j,proxyshell,proxylogon,spring4shell,exchange \
    -severity high,critical -timeout "${NUCLEI_TIMEOUT:-10}" -retries 1 \
    -o "$OUT/nuclei_critical.txt" -stats 2>/dev/null || true
  [[ -s "$OUT/nuclei_critical.txt" ]] && warn "Critical CVE hits -> $OUT/nuclei_critical.txt"
fi

# ---- SSL/TLS hygiene ------------------------------------------------------
if [[ -s "$RUN/web_urls.txt" ]] && have nmap; then
  log "TLS cipher/cert audit on HTTPS services"
  grep '^https' "$RUN/web_urls.txt" | sed 's#https://##' | while read -r hostport; do
    h=${hostport%%:*}; p=${hostport##*:}; [[ "$p" == "$h" ]] && p=443
    sudo nmap -Pn -p"$p" --script "ssl-enum-ciphers,ssl-cert,ssl-dh-params" "$h" \
      >>"$OUT/tls_audit.txt" 2>/dev/null || true
  done
  ok "TLS audit -> $OUT/tls_audit.txt"
fi

# ---- SNMP default community strings (network gear / IP switch) ------------
if [[ "$SKIP_UDP" != "true" ]] && have onesixtyone; then
  log "SNMP default community sweep (public/private)"
  printf 'public\nprivate\nmanager\ncisco\n' > "$OUT/snmp_comm.txt"
  run "$LOG" onesixtyone -c "$OUT/snmp_comm.txt" -i "$LIVE" -o "$OUT/snmp_hits.txt" || true

  # Where a community answered, walk system + process tables (info disclosure).
  if [[ -s "$OUT/snmp_hits.txt" ]] && have snmpwalk; then
    log "SNMP walk on hosts with a valid community"
    while read -r line; do
      sip=$(awk '{print $1}' <<<"$line")
      comm=$(grep -oP '\[\K[^\]]+' <<<"$line" | head -1)
      [[ -n "$sip" && -n "$comm" ]] || continue
      { echo "=== $sip (community: $comm) ==="
        snmpwalk -v2c -c "$comm" -t 2 -r 1 "$sip" 1.3.6.1.2.1.1            2>/dev/null   # system
        snmpwalk -v2c -c "$comm" -t 2 -r 1 "$sip" 1.3.6.1.2.1.25.4.2.1.2   2>/dev/null   # running processes
        snmpwalk -v2c -c "$comm" -t 2 -r 1 "$sip" 1.3.6.1.2.1.25.6.3.1.2   2>/dev/null   # installed software
      } >> "$OUT/snmp_walk.txt" 2>/dev/null || true
    done < "$OUT/snmp_hits.txt"
    [[ -s "$OUT/snmp_walk.txt" ]] && warn "SNMP info disclosure -> $OUT/snmp_walk.txt"
  fi
fi

ok "Vulnerability detection complete -> $OUT"
warn "These are DETECTIONS. Validate manually and stay within your rules of engagement before exploiting."
