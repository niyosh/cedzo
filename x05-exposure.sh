#!/usr/bin/env bash
# ==========================================================================
# 05-exposure.sh  -  Characterise the INTERNET-EXPOSED non-web services that
# phase 03 flagged: remote access (RDP/SSH/VNC/Telnet), databases, file
# services (FTP/SMB/NFS), directory services, edge/VPN appliances, SNMP.
#
# RECON ONLY: light banner reads and info/empty-password NSE scripts. NO
# authentication attempts, NO password spraying, NO brute force.
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh
RUN="${RUN:?RUN not set}"
OUT="$RUN/05-exposure"; mkdir -p "$OUT"; LOG="$OUT/exposure.log"

if [[ "${PASSIVE_ONLY:-false}" == "true" ]] && ! task_listing; then
  warn "PASSIVE_ONLY=true — skipping active exposure checks."; exit 0
fi

phase "Internet-Exposed Service Review"

# Combine a per-host port list (ip -> "p1,p2") for the NSE helpers.
HP="$RUN/03-portscan/host_ports.txt"

# ---- Sub-task: remote-access services (RDP/SSH/VNC/Telnet) ----------------
t_remote_access() {
  : > "$OUT/remote_access.txt"
  local RDP="$RUN/hosts_rdp.txt" SSH="$RUN/hosts_ssh.txt" VNC="$RUN/hosts_vnc.txt"
  # RDP — NLA/security mode + cert (no auth attempt).
  if [[ -s "$RDP" ]]; then
    log "RDP security characterisation (nmap rdp NSE)"
    nmap -Pn -p3389 --script "rdp-ntlm-info,rdp-enum-encryption" -iL "$RDP" \
      >> "$OUT/remote_access.txt" 2>/dev/null || true
  fi
  # SSH — algorithms + auth methods (no login).
  if [[ -s "$SSH" ]]; then
    log "SSH characterisation (algos / auth methods)"
    nmap -Pn -p22 --script "ssh2-enum-algos,ssh-auth-methods,ssh-hostkey" -iL "$SSH" \
      >> "$OUT/remote_access.txt" 2>/dev/null || true
  fi
  # VNC — security types (no auth).
  if [[ -s "$VNC" ]]; then
    log "VNC characterisation (security types)"
    nmap -Pn -p5900-5901 --script "vnc-info,realvnc-auth-bypass,vnc-title" -iL "$VNC" \
      >> "$OUT/remote_access.txt" 2>/dev/null || true
  fi
  if [[ -s "$RUN/hosts_winrm.txt" ]]; then
    log "WinRM endpoint check"
    nmap -Pn -p5985,5986 --script "http-title" -iL "$RUN/hosts_winrm.txt" \
      >> "$OUT/remote_access.txt" 2>/dev/null || true
  fi
  [[ -s "$OUT/remote_access.txt" ]] && ok "Remote-access review -> $OUT/remote_access.txt" \
    || log "No exposed remote-access services to characterise."
}

# ---- Sub-task: exposed databases / datastores -----------------------------
# Info / empty-password checks ONLY (brute-force scripts deliberately excluded).
t_databases() {
  local DBH="$RUN/hosts_db.txt"
  [[ -s "$DBH" ]] || { warn "No exposed DB hosts — skipping."; return 0; }
  log "DB-focused NSE (info / empty-password / config checks; no brute force)"
  nmap -Pn -sV \
    -p 1433,1521,3306,5432,6379,9200,27017,5984,11211 \
    --script "ms-sql-info,ms-sql-empty-password,mysql-info,mysql-empty-password,mongodb-info,oracle-tns-version,redis-info,cassandra-info,couchdb-databases" \
    -iL "$DBH" -oN "$OUT/databases.txt" 2>/dev/null || true
  ok "Exposed-database review -> $OUT/databases.txt"
  grep -iE 'empty.password|no password|databases:' "$OUT/databases.txt" 2>/dev/null \
    && warn "Possible unauthenticated/empty-password datastore — verify manually." || true
}

# ---- Sub-task: file services (FTP / SMB / NFS) ----------------------------
t_file_services() {
  : > "$OUT/file_services.txt"
  local FTP="$RUN/hosts_ftp.txt" SMB="$RUN/hosts_smb.txt"
  if [[ -s "$FTP" ]]; then
    log "FTP anon / banner (ftp-anon, no creds)"
    nmap -Pn -p21 --script "ftp-anon,ftp-syst,banner" -iL "$FTP" \
      >> "$OUT/file_services.txt" 2>/dev/null || true
  fi
  if [[ -s "$SMB" ]]; then
    warn "SMB (445/139) is exposed to the Internet — this is itself a finding."
    log "SMB protocol/security-mode characterisation (no auth)"
    nmap -Pn -p445 --script "smb-protocols,smb2-security-mode,smb2-capabilities" -iL "$SMB" \
      >> "$OUT/file_services.txt" 2>/dev/null || true
  fi
  if [[ -s "$RUN/hosts_smb.txt" ]] && have showmount; then
    log "NFS export listing (read-only) where rpcbind/NFS exposed"
    local ip
    while read -r ip; do
      [[ -n "$ip" ]] || continue
      out=$(showmount -e "$ip" 2>/dev/null || true)
      [[ -n "$out" ]] && { echo "=== NFS exports $ip ==="; echo "$out"; } >> "$OUT/file_services.txt"
    done < "$RUN/hosts_smb.txt"
  fi
  [[ -s "$OUT/file_services.txt" ]] && ok "File-service review -> $OUT/file_services.txt" \
    || log "No exposed file services to characterise."
}

# ---- Sub-task: edge / VPN appliances + management panels ------------------
# Fingerprint the gear that most often carries internet-facing pre-auth CVEs:
# Citrix, Fortinet, Pulse/Ivanti, Palo Alto GlobalProtect, F5, Cisco ASA,
# SonicWall, Exchange/OWA, plus generic admin/login panels.
t_appliances() {
  local WEBL="$RUN/04-web/live_urls.txt"
  [[ -s "$WEBL" ]] || WEBL="$RUN/web_urls.txt"
  [[ -s "$WEBL" ]] || { warn "No web URLs to fingerprint for appliances — skipping."; return 0; }
  : > "$OUT/appliances.txt"; : > "$OUT/panels.txt"

  log "Fingerprinting edge/VPN appliances + admin panels (title/header/path probes)"
  local APP_RE='fortinet|fortigate|forticlient|citrix|netscaler|gateway/vpns|pulse secure|ivanti|globalprotect|palo alto|big-?ip|f5 networks|cisco asa|adaptive security|sonicwall|sslvpn|sophos|watchguard|outlook web|owa|exchange|rdweb|remote desktop|vmware horizon|vcenter|esxi'
  local PANEL_RE='login|sign in|admin|dashboard|console|manager|portal|webmail|phpmyadmin|cpanel|plesk|jenkins|gitlab|grafana|kibana|prometheus|portainer'

  local base body hdr
  while read -r base; do
    [[ -n "$base" ]] || continue
    hdr=$(curl -k -s -m 12 -D - -o /dev/null "$base" 2>/dev/null || true)
    body=$(curl -k -s -m 12 "$base" 2>/dev/null | tr -d '\0' | head -c 20000 || true)
    if grep -qiE "$APP_RE" <<<"$hdr$body"; then
      printf '%s\t%s\n' "$base" "$(grep -oiE "$APP_RE" <<<"$hdr$body" | sort -u | paste -sd, -)" >> "$OUT/appliances.txt"
    fi
    if grep -qiE "$PANEL_RE" <<<"$body"; then
      printf '%s\t%s\n' "$base" "$(grep -oiE "$PANEL_RE" <<<"$body" | tr 'A-Z' 'a-z' | sort -u | paste -sd, -)" >> "$OUT/panels.txt"
    fi
  done < "$WEBL"
  [[ -s "$OUT/appliances.txt" ]] && warn "Edge/VPN appliances detected -> $OUT/appliances.txt ($(_ai_count "$OUT/appliances.txt"))" \
    || ok "No edge/VPN appliance fingerprints matched."
  [[ -s "$OUT/panels.txt" ]] && ok "Management/login panels -> $OUT/panels.txt ($(_ai_count "$OUT/panels.txt"))"
}

# ---- Sub-task: SNMP default community sweep -------------------------------
t_snmp() {
  { [[ "$SKIP_UDP" != "true" || -s "$RUN/hosts_snmp.txt" ]] && have onesixtyone; } \
    || { warn "SNMP UDP skipped (SKIP_UDP) or onesixtyone missing — skipping."; return 0; }
  local LIVE="$RUN/live_hosts.txt"
  [[ -s "$LIVE" ]] || { warn "No hosts — skipping SNMP."; return 0; }
  log "SNMP default-community sweep (public/private/etc.)"
  printf 'public\nprivate\nmanager\ncisco\n' > "$OUT/snmp_comm.txt"
  onesixtyone -c "$OUT/snmp_comm.txt" -i "$LIVE" -o "$OUT/snmp.txt" 2>/dev/null || true
  [[ -s "$OUT/snmp.txt" ]] && warn "SNMP responded to a default community -> $OUT/snmp.txt" \
    || ok "No SNMP default-community responses."
}

task remote_access "Remote access (RDP/SSH/VNC/WinRM) characterise"  t_remote_access
task databases     "Exposed DB info/empty-password checks (no brute)" t_databases
task file_services "FTP anon / SMB / NFS exposure checks"            t_file_services
task appliances    "Edge/VPN appliance + admin-panel fingerprint"    t_appliances
task snmp          "SNMP default-community sweep"                    t_snmp
task ai            "AI: triage internet-exposed services"            ai_bridge_05
run_tasks

ok "Exposed-service review complete -> $OUT"
warn "These are exposures/observations — validate within your RoE before any follow-up."
