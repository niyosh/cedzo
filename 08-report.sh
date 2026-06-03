#!/usr/bin/env bash
# ==========================================================================
# 08-report.sh  -  Consolidate every module's output into a single
#                  enterprise-ready Markdown report: $RUN/REPORT.md
# Read-only over the run directory; produces no network traffic.
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh
RUN="${RUN:?RUN not set}"
REPORT="$RUN/REPORT.md"

phase "Consolidated Reporting"

# Helpers -------------------------------------------------------------------
count() { [[ -s "$1" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }   # lines in file or 0
emit()  { printf '%s\n' "$*" >> "$REPORT"; }
section_file() {                       # heading, file, fenced? -> append if non-empty
  local title="$1" file="$2" fence="${3:-yes}"
  [[ -s "$file" ]] || return 0
  emit ""; emit "### $title"; emit ""
  if [[ "$fence" == "yes" ]]; then emit '```'; cat "$file" >> "$REPORT"; emit '```'
  else cat "$file" >> "$REPORT"; fi
}
RID=0
risk() {                                   # severity, finding, evidence
  RID=$((RID+1))
  printf '| RK-%03d | **%s** | %s | `%s` |\n' "$RID" "$1" "$2" "$3" >> "$REPORT"
}
fhit() { [[ -s "$1" ]] && grep -qiE "$2" "$1" 2>/dev/null; }   # file non-empty AND matches
gly()  { ls $1 >/dev/null 2>&1; }                              # glob has a match

# ---- Sub-task: secret scan over collected loot (noseyparker) --------------
# Scans everything this run collected (exposure dumps, AXFR/LDAP output, NFS
# listings, share indexes) for hardcoded secrets/keys. Runs before the rollup
# so any hit can be promoted into the Top-Risks table below.
t_secret_scan() {
  { [[ "${SECRET_SCAN:-true}" == "true" ]] && have noseyparker; } \
    || { warn "SECRET_SCAN disabled or noseyparker missing — skipping."; return 0; }
  log "noseyparker secret scan over $RUN"
  noseyparker scan --datastore "$RUN/.np_ds" "$RUN" >/dev/null 2>&1 || true
  noseyparker report --datastore "$RUN/.np_ds" > "$RUN/secrets_report.txt" 2>/dev/null || true
  [[ -s "$RUN/secrets_report.txt" ]] && warn "Potential secrets in loot -> $RUN/secrets_report.txt"
}

# ---- Sub-task: build the consolidated Markdown report ---------------------
t_markdown() {
  # Header --------------------------------------------------------------------
  : > "$REPORT"
  emit "# Internal Network Recon Report"
  emit ""
  emit "- **Generated:** $(date '+%Y-%m-%d %H:%M:%S %Z')"
  emit "- **Run directory:** \`$RUN\`"
  emit "- **Scope file:** \`$SCOPE_FILE\` ($(count "$RUN/scope.txt") entries)"
  emit "- **Engagement type:** Recon-only (no exploitation, spraying, brute force, or disruptive actions)"
  emit ""

  # Executive summary table ---------------------------------------------------
  emit "## Asset Summary"
  emit ""
  emit "| Metric | Count |"
  emit "|--------|-------|"
  emit "| Hosts in scope (treated live) | $(count "$RUN/live_hosts.txt") |"
  emit "| Hosts with open TCP ports | $(count "$RUN/02-portscan/host_ports.txt") |"
  emit "| SMB hosts | $(count "$RUN/hosts_smb.txt") |"
  emit "| Domain Controllers | $(count "$RUN/hosts_dc.txt") |"
  emit "| Web services | $(count "$RUN/web_urls.txt") |"
  emit "| Database hosts | $(count "$RUN/hosts_db.txt") |"
  emit "| RDP hosts | $(count "$RUN/hosts_rdp.txt") |"
  emit "| WinRM hosts | $(count "$RUN/hosts_winrm.txt") |"
  emit "| NFS hosts | $(count "$RUN/hosts_nfs.txt") |"
  emit "| Harvested domain users | $(count "$RUN/domain_users.txt") |"
  emit ""

  # Executive summary — prioritised top risks ---------------------------------
  # Heuristic rollup over the evidence collected by the other phases. Each row is
  # a high-signal observation worth triaging first; full detail is linked.
  emit "## Executive Summary — Top Risks (prioritised)"
  emit ""
  emit "| ID | Severity | Finding | Evidence |"
  emit "|----|----------|---------|----------|"
  RID=0

  # --- CRITICAL ---
  fhit "$RUN/07-vuln/smb_vuln_summary.txt" 'ms17-010|VULNERABLE' \
    && risk CRITICAL "MS17-010 / SMB EternalBlue indicated" "$RUN/07-vuln/smb_vuln_summary.txt"
  fhit "$RUN/07-vuln/nxc_vuln_summary.txt" 'zerologon|VULNERABLE' \
    && risk CRITICAL "Zerologon / netexec vuln-module hit" "$RUN/07-vuln/nxc_vuln_summary.txt"
  fhit "$RUN/07-vuln/smbghost.txt" 'VULNERABLE|cve-2020-0796' \
    && risk CRITICAL "SMBGhost (CVE-2020-0796) indicated" "$RUN/07-vuln/smbghost.txt"
  fhit "$RUN/07-vuln/bluekeep.txt" 'VULNERABLE' \
    && risk CRITICAL "BlueKeep (CVE-2019-0708) candidate" "$RUN/07-vuln/bluekeep.txt"
  [[ -s "$RUN/07-vuln/nuclei_critical.txt" ]] \
    && risk CRITICAL "High-impact web CVE (Log4Shell/ProxyShell/etc.)" "$RUN/07-vuln/nuclei_critical.txt"
  [[ -s "$RUN/06-ad-recon/adcs_summary.txt" ]] \
    && risk CRITICAL "ADCS vulnerable certificate template (ESCx)" "$RUN/06-ad-recon/adcs_summary.txt"

  # --- HIGH ---
  [[ -s "$RUN/03-smb-ad/gpp_creds.txt" ]] \
    && risk HIGH "GPP cpassword credentials recovered from SYSVOL" "$RUN/03-smb-ad/gpp_creds.txt"
  gly "$RUN/03-smb-ad/axfr_*.txt" \
    && risk HIGH "DNS zone transfer (AXFR) allowed" "$RUN/03-smb-ad/"
  gly "$RUN/03-smb-ad/ldap_anon_*.txt" \
    && risk HIGH "Anonymous LDAP bind allowed" "$RUN/03-smb-ad/"
  [[ -s "$RUN/03-smb-ad/nfs_exports.txt" ]] \
    && risk HIGH "NFS exports reachable" "$RUN/03-smb-ad/nfs_exports.txt"
  [[ "$(count "$RUN/06-ad-recon/kerberoast_hashes.txt")" -gt 0 ]] \
    && risk HIGH "Kerberoastable accounts ($(count "$RUN/06-ad-recon/kerberoast_hashes.txt") hashes; crack offline)" "$RUN/06-ad-recon/kerberoast_hashes.txt"
  [[ "$(count "$RUN/06-ad-recon/asrep_hashes.txt")" -gt 0 ]] \
    && risk HIGH "AS-REP roastable accounts (crack offline)" "$RUN/06-ad-recon/asrep_hashes.txt"
  fhit "$RUN/05-db/db_nse.nmap" 'empty.password|No password was|Login Success' \
    && risk HIGH "Database with empty/weak password" "$RUN/05-db/db_nse.nmap"
  [[ -s "$RUN/04-web/exposures.txt" ]] \
    && risk HIGH "Exposed sensitive web paths (.git/.env/backups/status)" "$RUN/04-web/exposures.txt"
  [[ -s "$RUN/secrets_report.txt" ]] \
    && risk HIGH "Secrets detected in collected loot (noseyparker)" "$RUN/secrets_report.txt"
  [[ -s "$RUN/06-ad-recon/ldap/desc_creds.txt" ]] \
    && risk HIGH "Passwords in AD user description / userPassword attributes" "$RUN/06-ad-recon/ldap/desc_creds.txt"
  [[ "$(count "$RUN/06-ad-recon/timeroast_hashes.txt")" -gt 0 ]] \
    && risk HIGH "Timeroastable computer accounts (crack offline, hashcat -m 31300)" "$RUN/06-ad-recon/timeroast_hashes.txt"
  gly "$RUN/03-smb-ad/dnsrecon_*.json" \
    && risk MEDIUM "Internal DNS enumeration (records/SRV/AXFR via dnsrecon)" "$RUN/03-smb-ad/"
  [[ -s "$RUN/04-web/ntlmrecon.csv" || -s "$RUN/04-web/ntlmrecon.txt" ]] \
    && risk MEDIUM "Internal AD info disclosed via NTLM endpoints" "$RUN/04-web/ntlmrecon.csv"

  # --- MEDIUM ---
  grep -rqiE 'message_signing: disabled' "$RUN/02-portscan/hosts"/*/service.nmap 2>/dev/null \
    && risk MEDIUM "SMB signing disabled (NTLM relay risk)" "$RUN/02-portscan/hosts/"
  fhit "$RUN/07-vuln/snmp_hits.txt" '\[' \
    && risk MEDIUM "SNMP default community string" "$RUN/07-vuln/snmp_hits.txt"
  [[ -s "$RUN/07-vuln/snmp_walk.txt" ]] \
    && risk MEDIUM "SNMP information disclosure (walked)" "$RUN/07-vuln/snmp_walk.txt"

  [[ "$RID" -eq 0 ]] && emit "| — | — | No high-level risks auto-detected — review evidence sections below | — |"
  emit ""
  emit "_Severity is a triage heuristic, not a CVSS score. Confirm each finding before reporting._"
  emit ""

  # Per-role host lists -------------------------------------------------------
  emit "## Hosts by Role"
  local role f
  for role in smb dc web db rdp winrm nfs; do
    f="$RUN/hosts_$role.txt"
    [[ -s "$f" ]] || continue
    emit ""; emit "### ${role^^} ($(count "$f"))"; emit '```'
    cat "$f" >> "$REPORT"; emit '```'
  done
  emit ""

  # Open ports map ------------------------------------------------------------
  section_file "Open Ports (host → ports)" "$RUN/02-portscan/host_ports.txt"

  # Web findings --------------------------------------------------------------
  emit ""; emit "## Web"
  section_file "httpx fingerprint" "$RUN/04-web/httpx.txt"
  if [[ -s "$RUN/04-web/nuclei.txt" ]]; then
    emit ""; emit "### nuclei findings ($(count "$RUN/04-web/nuclei.txt"))"; emit '```'
    cat "$RUN/04-web/nuclei.txt" >> "$REPORT"; emit '```'
  fi
  [[ -d "$RUN/04-web/screens" ]] && { emit ""; emit "Screenshots: \`$RUN/04-web/screens/\`"; }
  section_file "Exposed paths (.git/.env/backups/status)" "$RUN/04-web/exposures.txt"
  section_file "Favicon hashes (mmh3)" "$RUN/04-web/favicon.txt"
  section_file "IIS short-name disclosure (shortscan)" "$RUN/04-web/shortscan.txt"
  ls "$RUN/04-web"/wpscan_*.txt >/dev/null 2>&1 && { emit ""; emit "WordPress scans: \`$RUN/04-web/wpscan_*.txt\`"; }
  [[ -s "$RUN/04-web/ntlmrecon.csv" ]] && { emit ""; emit "NTLM endpoint recon: \`$RUN/04-web/ntlmrecon.csv\`"; }
  [[ -s "$RUN/04-web/ntlmrecon.txt" ]] && section_file "NTLM endpoint recon" "$RUN/04-web/ntlmrecon.txt"
  [[ -s "$RUN/04-web/cmseek.txt" ]] && { emit ""; emit "CMSeeK: \`$RUN/04-web/cmseek.txt\`"; }

  # SMB / AD enumeration ------------------------------------------------------
  emit ""; emit "## SMB / Active Directory"
  section_file "Enumerated users" "$RUN/03-smb-ad/users.txt"
  [[ -d "$RUN/03-smb-ad" ]] && {
    local shares; shares=$(ls "$RUN/03-smb-ad"/shares* 2>/dev/null | head -1 || true)
    [[ -n "$shares" ]] && section_file "Shares" "$shares"
  }
  section_file "GPP credentials (SYSVOL)" "$RUN/03-smb-ad/gpp_creds.txt"
  ls "$RUN/03-smb-ad"/ldap_anon_*.txt >/dev/null 2>&1 && { emit ""; emit "Anonymous LDAP dumps: \`$RUN/03-smb-ad/ldap_anon_*.txt\`"; }
  ls "$RUN/03-smb-ad"/axfr_*.txt >/dev/null 2>&1 && { emit ""; emit "DNS zone transfers: \`$RUN/03-smb-ad/axfr_*.txt\`"; }
  ls "$RUN/03-smb-ad"/dnsrecon_*.json >/dev/null 2>&1 && { emit ""; emit "dnsrecon output: \`$RUN/03-smb-ad/dnsrecon_*.json\`"; }
  section_file "Kerberos-validated usernames (kerbrute)" "$RUN/06-ad-recon/valid_users.txt"

  # NFS file services ---------------------------------------------------------
  if [[ -s "$RUN/03-smb-ad/nfs_exports.txt" ]]; then
    emit ""; emit "## NFS"
    section_file "Exports" "$RUN/03-smb-ad/nfs_exports.txt"
    [[ -s "$RUN/03-smb-ad/nfs_listing.txt" ]] && { emit ""; emit "Top-level listings: \`$RUN/03-smb-ad/nfs_listing.txt\`"; }
  fi

  # Database enumeration ------------------------------------------------------
  emit ""; emit "## Databases"
  section_file "DB NSE results" "$RUN/05-db/db_nse.nmap"

  # Vulnerability DETECTIONS (non-exploitative) -------------------------------
  emit ""; emit "## Vulnerability Detections (non-exploitative — validate manually)"
  section_file "SMB vulnerability checks" "$RUN/07-vuln/smb_vuln_summary.txt"
  section_file "netexec vulnerability checks" "$RUN/07-vuln/nxc_vuln_summary.txt"
  section_file "BlueKeep (RDP) check" "$RUN/07-vuln/bluekeep.txt"
  section_file "Critical web CVE sweep (log4j/proxyshell/etc.)" "$RUN/07-vuln/nuclei_critical.txt"
  section_file "SNMP default-community hits" "$RUN/07-vuln/snmp_hits.txt"
  [[ -s "$RUN/07-vuln/snmp_walk.txt" ]]  && { emit ""; emit "SNMP walk detail: \`$RUN/07-vuln/snmp_walk.txt\`"; }
  [[ -s "$RUN/07-vuln/tls_audit.txt" ]] && { emit ""; emit "TLS audit detail: \`$RUN/07-vuln/tls_audit.txt\`"; }

  # AD recon collection -------------------------------------------------------
  emit ""; emit "## AD Recon Collection (crack OFFLINE, out of band)"
  local kr ar tr
  kr=$(count "$RUN/06-ad-recon/kerberoast_hashes.txt")
  ar=$(count "$RUN/06-ad-recon/asrep_hashes.txt")
  tr=$(count "$RUN/06-ad-recon/timeroast_hashes.txt")
  emit ""
  emit "- Kerberoast hashes collected: **$kr** (\`hashcat -m 13100\`)"
  emit "- AS-REP hashes collected: **$ar** (\`hashcat -m 18200\`)"
  emit "- Timeroast hashes collected: **$tr** (\`hashcat -m 31300\`)"
  [[ -d "$RUN/06-ad-recon/bloodhound" ]] && emit "- BloodHound data: \`$RUN/06-ad-recon/bloodhound/\` (import into BloodHound GUI)"
  [[ -s "$RUN/06-ad-recon/adcs_summary.txt" ]] && emit "- ADCS vulnerable templates: \`$RUN/06-ad-recon/adcs_summary.txt\` (Certipy)"
  [[ -d "$RUN/06-ad-recon/ldeep" ]] && emit "- ldeep full LDAP dump: \`$RUN/06-ad-recon/ldeep/\`"
  emit ""
  section_file "ADCS vulnerable templates (Certipy)" "$RUN/06-ad-recon/adcs_summary.txt"
  section_file "Passwords in LDAP descriptions / attributes" "$RUN/06-ad-recon/ldap/desc_creds.txt"
  section_file "Delegation enumeration (impacket findDelegation)" "$RUN/06-ad-recon/findDelegation.txt"
  section_file "SCCM / MECM discovery" "$RUN/06-ad-recon/sccm.txt"

  # Secrets in collected loot ------------------------------------------------
  if [[ -s "$RUN/secrets_report.txt" ]]; then
    emit ""; emit "## Secrets in Collected Loot (noseyparker)"
    emit ""; emit "Detected in evidence this run collected — validate and rotate as needed."
    section_file "noseyparker report" "$RUN/secrets_report.txt"
  fi

  emit "---"
  emit "_Recon-only engagement. All findings are observations or detections;"
  emit "no exploitation was performed. Validate every detection within your RoE_"
  emit "_before any follow-up action._"

  ok "Consolidated report -> $REPORT"
  have glow && glow "$REPORT" 2>/dev/null || true
}

# ---- Sub-task: HTML reports (infrastructure + web vuln) -------------------
# Render rich, shareable HTML alongside the Markdown summary. The Python
# reporters walk the run dir for *.nmap and nuclei *.txt output.
t_html() {
  if have python3; then
    phase "HTML Reporting"
    python3 reporting/nmap2html.py   -i "$RUN" -o "$RUN/nmap_report.html" 2>/dev/null \
      && ok "Infrastructure report -> $RUN/nmap_report.html" \
      || warn "nmap2html skipped (no parseable .nmap output?)"
    python3 reporting/nuclei2html.py -i "$RUN" -o "$RUN/web_report.html" 2>/dev/null \
      && ok "Web vulnerability report -> $RUN/web_report.html" \
      || warn "nuclei2html skipped (no nuclei output?)"
  else
    warn "python3 not found — skipping HTML reports (Markdown REPORT.md still generated)."
  fi
}

task secret_scan "Scan collected loot for secrets (noseyparker)" t_secret_scan
task markdown    "Build consolidated REPORT.md"                  t_markdown
task html        "Render HTML reports (nmap + nuclei)"           t_html
run_tasks
