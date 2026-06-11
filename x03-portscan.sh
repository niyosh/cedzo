#!/usr/bin/env bash
# ==========================================================================
# 03-portscan.sh  -  External TCP (+ optional UDP) port/service scan.
# Rate-limited and polite by default (this crosses the public Internet).
# Produces per-host service files, role-based host lists, web_urls.txt, and a
# risky_services.txt of services that should almost never face the Internet.
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh
RUN="${RUN:?RUN not set}"
OUT="$RUN/03-portscan"; mkdir -p "$OUT"; LOG="$OUT/portscan.log"
LIVE="$RUN/live_hosts.txt"

if [[ "${PASSIVE_ONLY:-false}" == "true" ]] && ! task_listing; then
  warn "PASSIVE_ONLY=true — skipping active port scanning."; exit 0
fi
task_listing || [[ -s "$LIVE" ]] || { err "No hosts to scan. Run 01/02 first."; exit 1; }

phase "External Port & Service Scanning"

# ---- helper: build host:ports map from whichever scanner ran --------------
build_map() {
  if [[ -f "$OUT/tcp.gnmap" ]]; then
    grep '/open/' "$OUT/tcp.gnmap" | while read -r line; do
      ip=$(awk '{print $2}' <<<"$line")
      ports=$(grep -oE '[0-9]+/open' <<<"$line" | cut -d/ -f1 | paste -sd, -)
      [[ -n "$ports" ]] && echo "$ip $ports"
    done
  elif [[ -f "$OUT/masscan.gnmap" ]]; then
    local ip port
    declare -A _mp=()
    while read -r line; do
      ip=$(grep -oE 'Host: [0-9.]+' <<<"$line" | awk '{print $2}')
      port=$(grep -oE '[0-9]+/open' <<<"$line" | head -1 | cut -d/ -f1)
      [[ -n "$ip" && -n "$port" ]] && _mp["$ip"]+="${_mp[$ip]:+,}$port"
    done < <(grep 'Ports:' "$OUT/masscan.gnmap")
    for ip in "${!_mp[@]}"; do echo "$ip ${_mp[$ip]}"; done
  fi
}

scan_host() {
  local ip="$1" ports="$2"
  local hd="$OUT/hosts/$ip"; mkdir -p "$hd"
  printf '%s[sCV]%s %s -> %s\n' "$C_DIM" "$C_RST" "$ip" "$ports"
  nmap -sCV -Pn -p"$ports" -T"$NMAP_TIMING" --max-retries "${MAX_RETRIES:-2}" \
    --version-intensity 6 "$ip" -oA "$hd/service" >/dev/null 2>&1 || true
}

classify() {
  local pat="$1" outfile="$2"
  grep -rilE "$pat" "$OUT/hosts"/*/service.nmap 2>/dev/null \
    | sed 's#.*/hosts/##; s#/service.nmap##' | sort -u > "$RUN/$outfile" || true
}

# ---- Sub-task: TCP discovery -> host_ports.txt ----------------------------
t_discover() {
  if [[ "${TCP_FULL:-false}" == "true" ]]; then
    log "Full TCP discovery (-p-) — rate-limited (this is the public Internet)"
    local pflag="-p-"
  else
    log "Top-${TCP_TOP_PORTS:-1000} TCP discovery — rate-limited"
    local pflag="--top-ports ${TCP_TOP_PORTS:-1000}"
  fi
  run "$LOG" nmap -sS $pflag --min-rate "$MIN_RATE" -T"$NMAP_TIMING" \
    --max-retries "${MAX_RETRIES:-2}" --open -Pn -iL "$LIVE" -oA "$OUT/tcp" || true
  build_map | sort -u > "$OUT/host_ports.txt"
  ok "Hosts with open TCP ports: $(_ai_count "$OUT/host_ports.txt")"
}

# ---- Sub-task: targeted -sCV on discovered open ports ---------------------
t_service_scan() {
  [[ -s "$OUT/host_ports.txt" ]] || { warn "No host_ports.txt — run the 'discover' task first."; return 0; }
  export -f scan_host; export OUT C_DIM C_RST NMAP_TIMING MAX_RETRIES
  log "Service/version + default scripts on open ports (parallel x$THREADS)"
  while read -r ip ports; do printf '%s\t%s\n' "$ip" "$ports"; done < "$OUT/host_ports.txt" \
    | xargs -P "$THREADS" -d '\n' -I{} bash -c 'IFS=$'"'"'\t'"'"' read -r ip ports <<<"{}"; scan_host "$ip" "$ports"'
}

# ---- Sub-task: top UDP (optional; off by default externally) --------------
t_udp() {
  if [[ "$SKIP_UDP" != "true" ]]; then
    log "Top-50 UDP scan (DNS/SNMP/NTP/IKE/etc.)"
    run "$LOG" nmap -sU --top-ports 50 --open --min-rate "$((MIN_RATE/2))" \
      -Pn -iL "$LIVE" -oA "$OUT/udp_top" || true
  else
    log "SKIP_UDP=true — skipping UDP scan (default for external)."
  fi
}

# ---- Sub-task: classify hosts into role buckets + web/risky lists ---------
t_classify() {
  phase "Role classification + exposure flagging (from service scans)"
  classify 'http|https|ssl/http'                              "hosts_web.txt"
  classify 'ms-wbt-server|rdp|port 3389'                      "hosts_rdp.txt"
  classify 'microsoft-ds|netbios-ssn|port 445|port 139'       "hosts_smb.txt"
  classify 'ms-sql|mysql|postgresql|oracle|mongodb|redis|port 1433|port 3306|port 5432|port 6379|port 27017' "hosts_db.txt"
  classify 'ssh|port 22'                                      "hosts_ssh.txt"
  classify 'ftp|port 21'                                      "hosts_ftp.txt"
  classify 'vnc|port 5900'                                    "hosts_vnc.txt"
  classify 'winrm|wsman|port 5985|port 5986'                  "hosts_winrm.txt"
  classify 'smtp|port 25|port 587|port 465'                   "hosts_smtp.txt"
  classify 'ldap|port 389|port 636'                           "hosts_ldap.txt"

  local f n
  for f in hosts_web hosts_rdp hosts_smb hosts_db hosts_ssh hosts_ftp hosts_vnc hosts_winrm hosts_smtp hosts_ldap; do
    n=$(_ai_count "$RUN/$f.txt")
    ok "$(printf '%-12s' "$f"): $n hosts"
  done

  # ---- Internet-exposed risky services -----------------------------------
  # Services that, when reachable from the public Internet, are findings in
  # themselves (management/remote-access, datastores, legacy cleartext, etc.).
  : > "$RUN/risky_services.txt"
  local nmapf ip line port svc
  for nmapf in "$OUT"/hosts/*/service.nmap; do
    [[ -f "$nmapf" ]] || continue
    ip=$(basename "$(dirname "$nmapf")")
    { grep -E '^[0-9]+/tcp +open' "$nmapf" 2>/dev/null || true; } | while read -r line; do
      port=$(cut -d/ -f1 <<<"$line")
      svc=$(awk '{print $3}' <<<"$line")
      case "$port" in
        3389) printf '%s\tRDP (3389)\tRemote Desktop exposed to Internet\t%s\n' "$ip" "$line" >> "$RUN/risky_services.txt" ;;
        445|139) printf '%s\tSMB (%s)\tSMB/file sharing exposed to Internet\t%s\n' "$ip" "$port" "$line" >> "$RUN/risky_services.txt" ;;
        1433|3306|5432|1521|27017|6379|5984|9200|9300|11211|5433) printf '%s\tDB (%s)\tDatabase/datastore exposed to Internet\t%s\n' "$ip" "$port" "$line" >> "$RUN/risky_services.txt" ;;
        5900|5901) printf '%s\tVNC (%s)\tRemote desktop (VNC) exposed to Internet\t%s\n' "$ip" "$port" "$line" >> "$RUN/risky_services.txt" ;;
        23) printf '%s\tTelnet (23)\tCleartext remote login exposed to Internet\t%s\n' "$ip" "$line" >> "$RUN/risky_services.txt" ;;
        21) printf '%s\tFTP (21)\tFTP exposed to Internet\t%s\n' "$ip" "$line" >> "$RUN/risky_services.txt" ;;
        5985|5986) printf '%s\tWinRM (%s)\tWindows Remote Management exposed\t%s\n' "$ip" "$port" "$line" >> "$RUN/risky_services.txt" ;;
        389|636|3268) printf '%s\tLDAP (%s)\tDirectory service exposed to Internet\t%s\n' "$ip" "$port" "$line" >> "$RUN/risky_services.txt" ;;
        135|593) printf '%s\tRPC (%s)\tMS-RPC endpoint exposed to Internet\t%s\n' "$ip" "$port" "$line" >> "$RUN/risky_services.txt" ;;
        2049) printf '%s\tNFS (2049)\tNFS exposed to Internet\t%s\n' "$ip" "$line" >> "$RUN/risky_services.txt" ;;
        161) printf '%s\tSNMP (161)\tSNMP exposed to Internet\t%s\n' "$ip" "$line" >> "$RUN/risky_services.txt" ;;
      esac
    done
  done
  if [[ -s "$RUN/risky_services.txt" ]]; then
    sort -u -o "$RUN/risky_services.txt" "$RUN/risky_services.txt"
    warn "Internet-exposed RISKY services: $(_ai_count "$RUN/risky_services.txt") -> $RUN/risky_services.txt"
  else
    ok "No high-risk management/datastore services found exposed."
  fi

  # ---- Build the web URL list (http/https) -------------------------------
  local WEB_PORTS_HTTP=" 80 81 591 2480 3000 5000 7001 7070 7080 8000 8008 8080 8081 8082 8088 8180 8280 8888 9000 9080 9090 "
  local WEB_PORTS_HTTPS=" 443 832 981 1311 4443 7443 8243 8443 9443 10443 "
  : > "$RUN/web_urls.txt"
  for nmapf in "$OUT"/hosts/*/service.nmap; do
    [[ -f "$nmapf" ]] || continue
    ip=$(basename "$(dirname "$nmapf")")
    { grep -E '^[0-9]+/tcp +open' "$nmapf" 2>/dev/null || true; } | while read -r line; do
      port=$(cut -d/ -f1 <<<"$line")
      if   grep -qiE 'https|ssl/http' <<<"$line" || [[ "$WEB_PORTS_HTTPS" == *" $port "* ]]; then
        echo "https://$ip:$port"
      elif grep -qiE 'http'           <<<"$line" || [[ "$WEB_PORTS_HTTP"  == *" $port "* ]]; then
        echo "http://$ip:$port"
      fi
    done
  done | sort -u >> "$RUN/web_urls.txt"

  # Also queue resolved hostnames (web apps are usually vhosted by name).
  if [[ -s "$OUT/host_ports.txt" && -s "$RUN/02-osint/subdomains.txt" ]]; then
    : # hostname-based URLs are added by the web phase from subdomains/httpx
  fi
  ok "Web URLs: $(_ai_count "$RUN/web_urls.txt") -> $RUN/web_urls.txt"
}

task discover     "TCP discovery (top-ports/full) -> host_ports.txt"  t_discover
task service_scan "Service/version + NSE on open ports (nmap -sCV)"   t_service_scan
task udp          "Top UDP scan (skipped if SKIP_UDP=true)"           t_udp
task classify     "Classify roles + risky exposures + web_urls.txt"   t_classify
task ai           "AI: triage external services + exposures"          ai_bridge_03
run_tasks

ok "Port/service scan complete -> $OUT"
