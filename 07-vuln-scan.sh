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

# ---- Sub-task: SMB vulns via NSE ------------------------------------------
t_smb_nse() {
  [[ -s "$SMB" ]] || { warn "No SMB hosts — skipping."; return 0; }
  log "SMB vuln NSE (MS17-010 EternalBlue, SMBGhost, etc.)"
  run "$LOG" sudo nmap -Pn -p445 \
    --script "smb-vuln-ms17-010,smb-vuln-cve-2017-7494,smb-vuln-ms08-067,smb-protocols,smb2-security-mode" \
    -iL "$SMB" -oA "$OUT/smb_vuln" 2>/dev/null || true
  grep -iE 'VULNERABLE|State:' "$OUT/smb_vuln.nmap" 2>/dev/null | tee "$OUT/smb_vuln_summary.txt" || true
}

# ---- Sub-task: netexec built-in vuln modules ------------------------------
t_nxc_modules() {
  { [[ -n "$NXC" ]] && [[ -s "$SMB" ]]; } || { warn "No netexec or no SMB hosts — skipping."; return 0; }
  local mod
  for mod in zerologon petitpotam printnightmare nopac ms17-010 spooler webdav; do
    log "nxc module: $mod"
    run "$LOG" "$NXC" smb "$SMB" -u '' -p '' -M "$mod" 2>/dev/null || true
  done | grep -iE 'VULNERABLE|enabled|True' | tee "$OUT/nxc_vuln_summary.txt" || true
}

# ---- Sub-task: Zerologon safe-check against DCs ---------------------------
t_zerologon() {
  { [[ -s "$DC" ]] && [[ -n "$NXC" ]]; } || { warn "No DCs or no netexec — skipping."; return 0; }
  log "Zerologon safe-check against DCs"
  run "$LOG" "$NXC" smb "$DC" -u '' -p '' -M zerologon 2>/dev/null || true
}

# ---- Sub-task: SMBGhost CVE-2020-0796 (SMBv3.1.1 compression) -------------
t_smbghost() {
  [[ -s "$SMB" ]] || { warn "No SMB hosts — skipping."; return 0; }
  log "SMBGhost (CVE-2020-0796) detection"
  run "$LOG" sudo nmap -Pn -p445 --script smb-vuln-cve-2020-0796 \
    -iL "$SMB" -oN "$OUT/smbghost.txt" 2>/dev/null || true
  grep -iE 'VULNERABLE|cve-2020-0796' "$OUT/smbghost.txt" 2>/dev/null \
    | tee -a "$OUT/smb_vuln_summary.txt" || true
}

# ---- Sub-task: BlueKeep CVE-2019-0708 (RDP) — safe check via rdpscan ------
t_bluekeep() {
  { [[ -s "$RDP" ]] && have rdpscan; } || { warn "No RDP hosts or rdpscan missing — skipping."; return 0; }
  log "BlueKeep (CVE-2019-0708) safe check on RDP hosts"
  local ip
  while read -r ip; do
    [[ -n "$ip" ]] || continue
    rdpscan "$ip" 2>/dev/null | tee -a "$OUT/bluekeep.txt" || true
  done < "$RDP"
  grep -i 'VULNERABLE' "$OUT/bluekeep.txt" 2>/dev/null && warn "BlueKeep candidates -> $OUT/bluekeep.txt" || true
}

# ---- Sub-task: targeted nuclei sweep for high-impact CVEs -----------------
# Log4Shell / ProxyShell / ProxyLogon / Spring4Shell against discovered web.
t_nuclei_cve() {
  { [[ -s "$RUN/web_urls.txt" ]] && have nuclei; } || { warn "No web URLs or nuclei missing — skipping."; return 0; }
  log "nuclei targeted CVE sweep (log4j, proxyshell, proxylogon, spring4shell)"
  run "$LOG" nuclei -l "$RUN/web_urls.txt" \
    -tags log4j,proxyshell,proxylogon,spring4shell,exchange \
    -severity high,critical -timeout "${NUCLEI_TIMEOUT:-10}" -retries 1 \
    -o "$OUT/nuclei_critical.txt" -stats 2>/dev/null || true
  [[ -s "$OUT/nuclei_critical.txt" ]] && warn "Critical CVE hits -> $OUT/nuclei_critical.txt"
}

# ---- Sub-task: SSL/TLS hygiene --------------------------------------------
# Prefer testssl.sh (protocols, ciphers, cert, BEAST/ROBOT/Heartbleed
# detection); fall back to nmap NSE when testssl is unavailable.
t_tls() {
  [[ -s "$RUN/web_urls.txt" ]] || { warn "No web URLs — skipping TLS audit."; return 0; }
  local TESTSSL=""; have testssl.sh && TESTSSL=testssl.sh || { have testssl && TESTSSL=testssl; }
  log "TLS audit on HTTPS services${TESTSSL:+ (testssl.sh)}"
  local hostport h p safe
  grep '^https' "$RUN/web_urls.txt" | sed 's#https://##' | while read -r hostport; do
    h=${hostport%%:*}; p=${hostport##*:}; [[ "$p" == "$h" ]] && p=443
    safe=$(sed 's#[^A-Za-z0-9]#_#g' <<<"${h}_${p}")
    if [[ -n "$TESTSSL" ]]; then
      "$TESTSSL" --quiet --color 0 --warnings off --severity LOW \
        --jsonfile "$OUT/testssl_$safe.json" "$h:$p" >>"$OUT/tls_audit.txt" 2>/dev/null || true
    elif have nmap; then
      sudo nmap -Pn -p"$p" --script "ssl-enum-ciphers,ssl-cert,ssl-dh-params" "$h" \
        >>"$OUT/tls_audit.txt" 2>/dev/null || true
    fi
  done
  ok "TLS audit -> $OUT/tls_audit.txt"
}

# ---- Sub-task: SNMP default community strings -----------------------------
t_snmp() {
  { [[ "$SKIP_UDP" != "true" ]] && have onesixtyone; } || { warn "SKIP_UDP set or onesixtyone missing — skipping SNMP."; return 0; }
  log "SNMP default community sweep (public/private)"
  printf 'public\nprivate\nmanager\ncisco\n' > "$OUT/snmp_comm.txt"
  run "$LOG" onesixtyone -c "$OUT/snmp_comm.txt" -i "$LIVE" -o "$OUT/snmp_hits.txt" || true

  # Where a community answered, walk system + process tables (info disclosure).
  if [[ -s "$OUT/snmp_hits.txt" ]] && have snmpwalk; then
    log "SNMP walk on hosts with a valid community"
    local line sip comm
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
}

task smb_nse     "SMB vuln NSE (MS17-010 EternalBlue, etc.)"        t_smb_nse
task nxc_modules "netexec vuln modules (zerologon/petitpotam/...)"  t_nxc_modules
task zerologon   "Zerologon safe-check against DCs"                 t_zerologon
task smbghost    "SMBGhost CVE-2020-0796 detection"                 t_smbghost
task bluekeep    "BlueKeep CVE-2019-0708 RDP safe-check"            t_bluekeep
task nuclei_cve  "Targeted nuclei CVE sweep (log4j/proxyshell/...)" t_nuclei_cve
task tls         "SSL/TLS hygiene audit (testssl/nmap)"             t_tls
task snmp        "SNMP default community sweep + walk"              t_snmp
task ai          "AI: correlate vuln detections"                   ai_bridge_07
run_tasks

ok "Vulnerability detection complete -> $OUT"
warn "These are DETECTIONS. Validate manually and stay within your rules of engagement before exploiting."
