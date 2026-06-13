#!/usr/bin/env bash
# ==========================================================================
# 02-portscan.sh  -  Full TCP + top UDP, then service/version + default NSE.
# Produces per-host service files and role-based host lists for later modules.
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh
RUN="${RUN:?RUN not set}"
OUT="$RUN/02-portscan"; mkdir -p "$OUT"; LOG="$OUT/portscan.log"
SCOPE_TMP=$(mktemp /tmp/scope_XXXXXX.txt)
clean_scope > "$SCOPE_TMP"
trap 'rm -f "$SCOPE_TMP"' EXIT
LIVE="$RUN/live_hosts.txt"
task_listing || [[ -s "$LIVE" ]] || { err "No live hosts. Run 01 first."; exit 1; }

phase "Port & Service Scanning"

# ---- helper: build host:ports map from whichever scanner ran --------------
build_map() {
  if [[ -f "$OUT/full_tcp.gnmap" ]]; then
    grep '/open/' "$OUT/full_tcp.gnmap" | while read -r line; do
      ip=$(awk '{print $2}' <<<"$line")
      ports=$(grep -oE '[0-9]+/open' <<<"$line" | cut -d/ -f1 | paste -sd, -)
      [[ -n "$ports" ]] && echo "$ip $ports"
    done
  elif [[ -f "$OUT/masscan.gnmap" ]]; then
    # masscan -oG writes ONE "Ports:" line per open port, so aggregate all
    # ports for each host into a single line (else we'd scan each port as a
    # separate job, all racing to write the same service.* file).
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
  sudo nmap -sCV -Pn -p"$ports" -T"$NMAP_TIMING" \
    --version-intensity 6 "$ip" -oA "$hd/service" >/dev/null 2>&1 || true
}

classify() {
  local pat="$1" outfile="$2"
  # A no-match grep exits 1; under `set -euo pipefail` that would abort the
  # whole module, so swallow it — an empty role list is a valid outcome.
  grep -rilE "$pat" "$OUT/hosts"/*/service.nmap 2>/dev/null \
    | sed 's#.*/hosts/##; s#/service.nmap##' | sort -u > "$RUN/$outfile" || true
}

# ---- Sub-task: fast full-TCP discovery -> host_ports.txt ------------------
t_discover() {
  log "Full TCP port discovery (-p- , masscan if available else nmap)"
  if have masscan; then
    run "$LOG" sudo masscan -p1-65535 --rate "$((MIN_RATE*5))" \
      -iL "$LIVE" -oG "$OUT/masscan.gnmap" || true
    awk '/Ports:/{ip=$4; gsub(/.*Ports: /,""); print ip" "$0}' "$OUT/masscan.gnmap" 2>/dev/null \
      > "$OUT/open_raw.txt" || true
  else
    run "$LOG" sudo nmap -sS -p- -Pn --min-rate "$MIN_RATE" -T"$NMAP_TIMING" \
      --open -iL "$LIVE" -oA "$OUT/full_tcp" || true
  fi
  build_map | sort -u > "$OUT/host_ports.txt"
  ok "Hosts with open TCP ports: $(wc -l < "$OUT/host_ports.txt")"
}

# ---- Sub-task: targeted -sCV on discovered open ports (per host) ----------
t_service_scan() {
  [[ -s "$OUT/host_ports.txt" ]] || { warn "No host_ports.txt — run the 'discover' task first."; return 0; }
  export -f scan_host; export OUT C_DIM C_RST NMAP_TIMING
  log "Service/version + default scripts on open ports (parallel x$THREADS)"
  while read -r ip ports; do printf '%s\t%s\n' "$ip" "$ports"; done < "$OUT/host_ports.txt" \
    | xargs -P "$THREADS" -d '\n' -I{} bash -c 'IFS=$'"'"'\t'"'"' read -r ip ports <<<"{}"; scan_host "$ip" "$ports"'
}

# ---- Sub-task: top UDP (slow) ---------------------------------------------
t_udp() {
  if [[ "$SKIP_UDP" != "true" ]]; then
    log "Top-${UDP_TOP_PORTS:-500} UDP scan (SNMP/DNS/NetBIOS/etc.)"
    run "$LOG" sudo nmap -sU --top-ports "${UDP_TOP_PORTS:-500}" -Pn --open --min-rate "$((MIN_RATE/2))" \
      -iL "$LIVE" -oA "$OUT/udp_top" || true
  else
    log "SKIP_UDP=true — skipping UDP scan."
  fi
}

# ---- Sub-task: classify hosts into role buckets + web URL list ------------
t_classify() {
  phase "Role classification (from service scans)"
  classify 'microsoft-ds|netbios-ssn|port 445'                "hosts_smb.txt"
  classify 'ldap|kerberos-sec|port 88|microsoft-ds.*Active'   "hosts_dc.txt"
  classify 'http|https|ssl/http'                              "hosts_web.txt"
  classify 'ms-sql|mysql|postgresql|oracle|mongodb'           "hosts_db.txt"
  classify 'ms-wbt-server|rdp|port 3389'                      "hosts_rdp.txt"
  classify 'winrm|wsman|port 5985'                            "hosts_winrm.txt"
  classify 'nfs|mountd|rpcbind|portmapper'                    "hosts_nfs.txt"

  local f n
  for f in hosts_smb hosts_dc hosts_web hosts_db hosts_rdp hosts_winrm hosts_nfs; do
    n=$( [[ -f "$RUN/$f.txt" ]] && wc -l < "$RUN/$f.txt" || echo 0 )
    ok "$(printf '%-12s' "$f"): $n hosts"
  done

  # Build a web URL list (http/https) for the web module.
  # Match on the service name AND on common web port numbers, so a port that
  # nmap fails to fingerprint (e.g. a slow Tomcat that comes back as "unknown")
  # is still treated as web. Surround with spaces for whole-token matching.
  local WEB_PORTS_HTTP=" 80 81 591 2480 3000 5000 7001 7070 7080 8000 8008 8080 8081 8082 8088 8180 8280 8888 9000 9080 9090 "
  local WEB_PORTS_HTTPS=" 443 832 981 1311 4443 7443 8243 8443 9443 "
  : > "$RUN/web_urls.txt"
  local nmapf ip port line
  for nmapf in "$OUT"/hosts/*/service.nmap; do
    [[ -f "$nmapf" ]] || continue          # glob didn't match -> no hosts
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
  ok "Web URLs: $(wc -l < "$RUN/web_urls.txt") -> $RUN/web_urls.txt"
}

task discover     "Full TCP discovery (masscan/nmap) -> host_ports.txt" t_discover
task service_scan "Service/version + NSE on open ports (nmap -sCV)"     t_service_scan
task udp          "Top-${UDP_TOP_PORTS:-500} UDP scan (set SKIP_UDP=true to skip)" t_udp
task classify     "Classify hosts by role + build web_urls.txt"         t_classify
task ai           "AI: triage services + prioritise hosts"             ai_bridge_02
run_tasks
