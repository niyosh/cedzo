#!/usr/bin/env bash
# ==========================================================================
# 07-vuln-scan.sh  -  Non-exploitative detection of high-impact EXTERNAL
# vulnerabilities: nuclei CVE sweep, edge/VPN appliance CVE checks, TLS/SSL
# hygiene, and SMTP open-relay detection. These are CHECKS — verify manually
# before any exploitation and stay within your rules of engagement.
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh
RUN="${RUN:?RUN not set}"
OUT="$RUN/07-vuln"; mkdir -p "$OUT"; LOG="$OUT/vuln.log"
WEBL="$RUN/04-web/live_urls.txt"; [[ -s "$WEBL" ]] || WEBL="$RUN/web_urls.txt"

if [[ "${PASSIVE_ONLY:-false}" == "true" ]] && ! task_listing; then
  warn "PASSIVE_ONLY=true — skipping active vuln detection."; exit 0
fi

phase "External Vulnerability Detection (non-exploitative)"

# ---- Sub-task: high/critical CVE sweep (nuclei) ---------------------------
t_nuclei_cve() {
  { [[ -s "$WEBL" ]] && have nuclei; } || { warn "No web URLs or nuclei missing — skipping."; return 0; }
  log "nuclei CVE + misconfig sweep (high/critical) over external web surface"
  run "$LOG" nuclei -l "$WEBL" \
    -tags cve,exposure,misconfig,default-login \
    -severity high,critical -timeout "${NUCLEI_TIMEOUT:-10}" -retries 1 \
    -rl "${NUCLEI_RATELIMIT:-100}" -c 25 -o "$OUT/nuclei_cve.txt" -stats 2>/dev/null || true
  [[ -s "$OUT/nuclei_cve.txt" ]] && warn "High/critical CVE hits -> $OUT/nuclei_cve.txt" \
    || ok "No high/critical nuclei CVE hits."
}

# ---- Sub-task: edge/VPN appliance CVE checks ------------------------------
# The internet-facing gear that most often carries pre-auth RCE/path-traversal.
t_appliance_cve() {
  { [[ -s "$WEBL" ]] && have nuclei; } || { warn "No web URLs or nuclei missing — skipping."; return 0; }
  # Prefer the appliance fingerprints from phase 05; fall back to all web URLs.
  local targets="$WEBL"
  if [[ -s "$RUN/05-exposure/appliances.txt" ]]; then
    cut -f1 "$RUN/05-exposure/appliances.txt" | sort -u > "$OUT/appliance_targets.txt"
    [[ -s "$OUT/appliance_targets.txt" ]] && targets="$OUT/appliance_targets.txt"
  fi
  log "nuclei edge/VPN appliance CVE checks (fortinet/citrix/pulse/f5/exchange/...)"
  run "$LOG" nuclei -l "$targets" \
    -tags fortinet,citrix,pulse,ivanti,globalprotect,panos,bigip,f5,sonicwall,exchange,proxyshell,proxylogon,vmware,confluence,gitlab,jira \
    -severity medium,high,critical -timeout "${NUCLEI_TIMEOUT:-10}" -retries 1 \
    -rl "${NUCLEI_RATELIMIT:-100}" -c 25 -o "$OUT/appliance_cve.txt" -stats 2>/dev/null || true
  [[ -s "$OUT/appliance_cve.txt" ]] && warn "Appliance CVE hits -> $OUT/appliance_cve.txt" \
    || ok "No appliance CVE hits."
}

# ---- Sub-task: TLS / SSL hygiene ------------------------------------------
t_tls() {
  [[ -s "$RUN/web_urls.txt" ]] || { warn "No web URLs — skipping TLS audit."; return 0; }
  : > "$OUT/tls_audit.txt"
  local hostport h p
  if have testssl.sh || have testssl; then
    local TS; TS=$(command -v testssl.sh || command -v testssl)
    log "TLS audit via testssl.sh (protocols/ciphers/vulns)"
    grep '^https' "$RUN/web_urls.txt" | sed 's#https://##' | sort -u | while read -r hostport; do
      { echo "===== $hostport ====="; "$TS" --quiet --color 0 --severity LOW "$hostport" 2>/dev/null; echo; } \
        >> "$OUT/tls_audit.txt" || true
    done
  elif have nmap; then
    log "TLS audit via nmap ssl NSE (testssl.sh not installed)"
    grep '^https' "$RUN/web_urls.txt" | sed 's#https://##' | sort -u | while read -r hostport; do
      h=${hostport%%:*}; p=${hostport##*:}; [[ "$p" == "$h" ]] && p=443
      nmap -Pn -p"$p" --script "ssl-enum-ciphers,ssl-cert,ssl-dh-params" "$h" \
        >> "$OUT/tls_audit.txt" 2>/dev/null || true
    done
  else
    warn "Neither testssl.sh nor nmap available — skipping TLS audit."; return 0
  fi
  ok "TLS audit -> $OUT/tls_audit.txt"
}

# ---- Sub-task: SMTP open-relay / banner check -----------------------------
# Banner + STARTTLS + relay TEST via nmap NSE (smtp-open-relay is a safe probe;
# it does not actually deliver mail to third parties).
t_smtp() {
  local SMTP="$RUN/hosts_smtp.txt"
  { [[ -s "$SMTP" ]] && have nmap; } || { warn "No SMTP hosts or nmap missing — skipping."; return 0; }
  log "SMTP banner / STARTTLS / open-relay detection (nmap NSE)"
  nmap -Pn -p25,465,587 \
    --script "smtp-commands,smtp-open-relay,smtp-ntlm-info,ssl-cert" \
    -iL "$SMTP" -oN "$OUT/smtp.txt" 2>/dev/null || true
  grep -iE 'open relay|relay.*allowed' "$OUT/smtp.txt" 2>/dev/null \
    && warn "Possible SMTP open relay -> $OUT/smtp.txt" || true
  ok "SMTP review -> $OUT/smtp.txt"
}

task nuclei_cve    "High/critical CVE sweep (nuclei)"               t_nuclei_cve
task appliance_cve "Edge/VPN appliance CVE checks (nuclei)"         t_appliance_cve
task tls           "TLS/SSL hygiene audit (testssl.sh / nmap)"      t_tls
task smtp          "SMTP open-relay + banner detection"            t_smtp
task ai            "AI: correlate external vuln detections"        ai_bridge_07
run_tasks

ok "Vulnerability detection complete -> $OUT"
warn "These are DETECTIONS. Validate manually and stay within your rules of engagement before exploiting."
