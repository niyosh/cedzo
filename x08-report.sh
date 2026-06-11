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
count() { [[ -s "$1" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }
emit()  { printf '%s\n' "$*" >> "$REPORT"; }
section_file() {
  local title="$1" file="$2" fence="${3:-yes}"
  [[ -s "$file" ]] || return 0
  emit ""; emit "### $title"; emit ""
  if [[ "$fence" == "yes" ]]; then emit '```'; cat "$file" >> "$REPORT"; emit '```'
  else cat "$file" >> "$REPORT"; fi
}
RID=0
risk() {
  RID=$((RID+1))
  printf '| RK-%03d | **%s** | %s | `%s` |\n' "$RID" "$1" "$2" "$3" >> "$REPORT"
}
fhit() { [[ -s "$1" ]] && grep -qiE "$2" "$1" 2>/dev/null; }
gly()  { ls $1 >/dev/null 2>&1; }

# ---- Sub-task: secret scan over collected loot (noseyparker) --------------
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
  : > "$REPORT"
  emit "# External Attack-Surface Recon Report"
  emit ""
  emit "- **Generated:** $(date '+%Y-%m-%d %H:%M:%S %Z')"
  emit "- **Run directory:** \`$RUN\`"
  emit "- **Scope file:** \`$SCOPE_FILE\` ($(count "$RUN/scope.txt") entries)"
  emit "- **Engagement type:** External recon-only (no exploitation, spraying, brute force, or disruptive actions)"
  [[ -n "${TARGET_DOMAIN:-}" ]] && emit "- **Primary domain:** \`$TARGET_DOMAIN\`"
  emit ""

  # Asset summary -------------------------------------------------------------
  emit "## Asset Summary"
  emit ""
  emit "| Metric | Count |"
  emit "|--------|-------|"
  emit "| IP/range targets in scope | $(count "$RUN/ip_targets.txt") |"
  emit "| Domain targets in scope | $(count "$RUN/domain_targets.txt") |"
  emit "| Subdomains discovered | $(count "$RUN/02-osint/subdomains.txt") |"
  emit "| Public IPs resolved | $(count "$RUN/resolved_hosts.txt") |"
  emit "| Hosts scanned | $(count "$RUN/live_hosts.txt") |"
  emit "| Hosts with open TCP ports | $(count "$RUN/03-portscan/host_ports.txt") |"
  emit "| Internet-exposed risky services | $(count "$RUN/risky_services.txt") |"
  emit "| Web services | $(count "$RUN/web_urls.txt") |"
  emit "| RDP hosts | $(count "$RUN/hosts_rdp.txt") |"
  emit "| Exposed DB hosts | $(count "$RUN/hosts_db.txt") |"
  emit "| Edge/VPN appliances | $(count "$RUN/05-exposure/appliances.txt") |"
  emit "| Subdomain-takeover candidates | $(count "$RUN/06-takeover/takeover.txt") |"
  emit ""

  # Executive summary — prioritised top risks ---------------------------------
  emit "## Executive Summary — Top Risks (prioritised)"
  emit ""
  emit "| ID | Severity | Finding | Evidence |"
  emit "|----|----------|---------|----------|"
  RID=0

  # --- CRITICAL ---
  [[ -s "$RUN/07-vuln/appliance_cve.txt" ]] \
    && risk CRITICAL "Edge/VPN appliance with known CVE indicated" "$RUN/07-vuln/appliance_cve.txt"
  [[ -s "$RUN/07-vuln/nuclei_cve.txt" ]] \
    && risk CRITICAL "High/critical web CVE (nuclei)" "$RUN/07-vuln/nuclei_cve.txt"
  fhit "$RUN/06-takeover/takeover.txt" 'vulnerable|takeover|is taken|can be' \
    && risk CRITICAL "Subdomain takeover candidate" "$RUN/06-takeover/takeover.txt"
  fhit "$RUN/06-takeover/buckets.txt" 'PUBLIC-LISTABLE' \
    && risk CRITICAL "Publicly listable cloud storage bucket" "$RUN/06-takeover/buckets.txt"
  fhit "$RUN/05-exposure/databases.txt" 'empty.password|no password|Login Success' \
    && risk CRITICAL "Internet-exposed database with empty/no password" "$RUN/05-exposure/databases.txt"

  # --- HIGH ---
  fhit "$RUN/risky_services.txt" 'RDP' \
    && risk HIGH "RDP (3389) exposed to the Internet" "$RUN/risky_services.txt"
  fhit "$RUN/risky_services.txt" 'SMB' \
    && risk HIGH "SMB (445/139) exposed to the Internet" "$RUN/risky_services.txt"
  fhit "$RUN/risky_services.txt" 'DB ' \
    && risk HIGH "Database service exposed to the Internet" "$RUN/risky_services.txt"
  fhit "$RUN/risky_services.txt" 'Telnet|VNC' \
    && risk HIGH "Cleartext/legacy remote access (Telnet/VNC) exposed" "$RUN/risky_services.txt"
  [[ -s "$RUN/05-exposure/appliances.txt" ]] \
    && risk HIGH "Internet-facing edge/VPN appliance (patch + monitor)" "$RUN/05-exposure/appliances.txt"
  [[ -s "$RUN/04-web/exposures.txt" ]] \
    && risk HIGH "Exposed sensitive web paths (.git/.env/backups/status)" "$RUN/04-web/exposures.txt"
  [[ -s "$RUN/06-takeover/exposed_git.txt" ]] \
    && risk HIGH "Exposed source repository / secret file" "$RUN/06-takeover/exposed_git.txt"
  [[ -s "$RUN/secrets_report.txt" ]] \
    && risk HIGH "Secrets detected in collected loot (noseyparker)" "$RUN/secrets_report.txt"
  fhit "$RUN/07-vuln/smtp.txt" 'open relay|relay.*allowed' \
    && risk HIGH "SMTP open relay" "$RUN/07-vuln/smtp.txt"

  # --- MEDIUM ---
  fhit "$RUN/02-osint/email_security.txt" 'MISSING' \
    && risk MEDIUM "Weak/missing SPF or DMARC (email spoofing risk)" "$RUN/02-osint/email_security.txt"
  fhit "$RUN/07-vuln/tls_audit.txt" 'SSLv2|SSLv3|TLSv1\.0|RC4|EXPORT|NULL|self-signed|expired' \
    && risk MEDIUM "Weak TLS configuration / certificate issues" "$RUN/07-vuln/tls_audit.txt"
  fhit "$RUN/05-exposure/snmp.txt" '\[' \
    && risk MEDIUM "SNMP default community string exposed" "$RUN/05-exposure/snmp.txt"
  [[ -s "$RUN/05-exposure/panels.txt" ]] \
    && risk MEDIUM "Internet-facing admin/login panels" "$RUN/05-exposure/panels.txt"
  [[ -s "$RUN/06-takeover/dangling_cnames.txt" ]] \
    && risk MEDIUM "Dangling CNAMEs to third-party services" "$RUN/06-takeover/dangling_cnames.txt"

  [[ "$RID" -eq 0 ]] && emit "| — | — | No high-level risks auto-detected — review evidence sections below | — |"
  emit ""
  emit "_Severity is a triage heuristic, not a CVSS score. Confirm each finding before reporting._"
  emit ""

  # OSINT ---------------------------------------------------------------------
  emit "## OSINT / Footprint"
  section_file "Subdomains" "$RUN/02-osint/subdomains.txt"
  section_file "Resolved public IPs" "$RUN/resolved_hosts.txt"
  section_file "Email authentication (SPF/DKIM/DMARC)" "$RUN/02-osint/email_security.txt"
  section_file "DNS records" "$RUN/02-osint/dns_records.txt"
  section_file "WHOIS / ASN context" "$RUN/02-osint/whois_asn.txt"
  section_file "Reverse DNS" "$RUN/02-osint/reverse_dns.txt"

  # Internet-exposed services -------------------------------------------------
  emit ""; emit "## Internet-Exposed Services"
  section_file "Risky exposures (host, service, why)" "$RUN/risky_services.txt"
  section_file "Remote access (RDP/SSH/VNC/WinRM)" "$RUN/05-exposure/remote_access.txt"
  section_file "Exposed databases" "$RUN/05-exposure/databases.txt"
  section_file "File services (FTP/SMB/NFS)" "$RUN/05-exposure/file_services.txt"
  section_file "Edge/VPN appliances" "$RUN/05-exposure/appliances.txt" no
  section_file "Management / login panels" "$RUN/05-exposure/panels.txt" no
  section_file "SNMP default-community hits" "$RUN/05-exposure/snmp.txt"

  # Open ports ----------------------------------------------------------------
  section_file "Open Ports (host → ports)" "$RUN/03-portscan/host_ports.txt"

  # Web findings --------------------------------------------------------------
  emit ""; emit "## Web"
  section_file "httpx fingerprint" "$RUN/04-web/httpx.txt"
  if [[ -s "$RUN/04-web/nuclei.txt" ]]; then
    emit ""; emit "### nuclei findings ($(count "$RUN/04-web/nuclei.txt"))"; emit '```'
    cat "$RUN/04-web/nuclei.txt" >> "$REPORT"; emit '```'
  fi
  if [[ -s "$RUN/04-web/nuclei_ai.txt" ]]; then
    emit ""; emit "### nuclei findings — AI-targeted pass ($(count "$RUN/04-web/nuclei_ai.txt"))"; emit '```'
    cat "$RUN/04-web/nuclei_ai.txt" >> "$REPORT"; emit '```'
  fi
  [[ -d "$RUN/04-web/screens" ]] && { emit ""; emit "Screenshots: \`$RUN/04-web/screens/\`"; }
  section_file "Exposed paths (.git/.env/backups/status)" "$RUN/04-web/exposures.txt"
  section_file "Favicon hashes (mmh3)" "$RUN/04-web/favicon.txt"
  ls "$RUN/04-web"/wpscan_*.txt >/dev/null 2>&1 && { emit ""; emit "WordPress scans: \`$RUN/04-web/wpscan_*.txt\`"; }

  # Takeover / cloud ----------------------------------------------------------
  emit ""; emit "## Subdomain Takeover / Cloud Exposure"
  section_file "Takeover candidates" "$RUN/06-takeover/takeover.txt"
  section_file "Dangling CNAMEs" "$RUN/06-takeover/dangling_cnames.txt" no
  section_file "Cloud storage buckets" "$RUN/06-takeover/buckets.txt" no
  section_file "Exposed VCS / secret files" "$RUN/06-takeover/exposed_git.txt"

  # Vulnerability detections --------------------------------------------------
  emit ""; emit "## Vulnerability Detections (non-exploitative — validate manually)"
  section_file "High/critical CVE sweep (nuclei)" "$RUN/07-vuln/nuclei_cve.txt"
  section_file "Edge/VPN appliance CVE checks" "$RUN/07-vuln/appliance_cve.txt"
  section_file "SMTP open-relay / banner" "$RUN/07-vuln/smtp.txt"
  [[ -s "$RUN/07-vuln/tls_audit.txt" ]] && { emit ""; emit "TLS audit detail: \`$RUN/07-vuln/tls_audit.txt\`"; }

  # Secrets -------------------------------------------------------------------
  if [[ -s "$RUN/secrets_report.txt" ]]; then
    emit ""; emit "## Secrets in Collected Loot (noseyparker)"
    emit ""; emit "Detected in evidence this run collected — validate and rotate as needed."
    section_file "noseyparker report" "$RUN/secrets_report.txt"
  fi

  # Per-phase AI analysis -----------------------------------------------------
  if ls "$RUN/ai"/0*-*.md >/dev/null 2>&1; then
    emit ""; emit "## AI Per-Phase Analysis"
    emit ""; emit "_AI-generated triage, one file per phase. Guidance only — validate against the evidence above._"
    local aimd
    for aimd in "$RUN/ai"/0*-*.md; do
      [[ -s "$aimd" ]] && emit "- \`$aimd\`"
    done
  fi
  emit ""

  emit "---"
  emit "_External recon-only engagement. All findings are observations or detections;"
  emit "no exploitation was performed. Validate every detection within your RoE_"
  emit "_before any follow-up action._"

  ok "Consolidated report -> $REPORT"
  have glow && glow "$REPORT" 2>/dev/null || true
}

# ---- Sub-task: HTML reports (infrastructure + web vuln) -------------------
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
task ai_summary  "AI: executive summary (injected into REPORT)"  ai_exec_summary
task html        "Render HTML reports (nmap + nuclei)"           t_html
run_tasks
