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
[[ -s "$LIVE" ]] || { err "No live hosts. Run 01 first."; exit 1; }

phase "Port & Service Scanning"

# ---- Phase A: fast full-TCP discovery across all hosts --------------------
log "Full TCP port discovery (-p- , masscan if available else nmap)"
if have masscan; then
  run "$LOG" sudo masscan -p1-65535 --rate "$((MIN_RATE*5))" \
    -iL "$LIVE" -oG "$OUT/masscan.gnmap" || true
  # extract host->ports from masscan
  awk '/Ports:/{ip=$4; gsub(/.*Ports: /,""); print ip" "$0}' "$OUT/masscan.gnmap" 2>/dev/null \
    > "$OUT/open_raw.txt" || true
else
  run "$LOG" sudo nmap -sS -p- --min-rate "$MIN_RATE" -T"$NMAP_TIMING" \
    --open -iL "$LIVE" -oA "$OUT/full_tcp" || true
fi

# ---- Phase B: targeted -sCV on discovered open ports (per host) -----------
# Build a host:ports map from whichever scanner ran.
build_map() {
  if [[ -f "$OUT/full_tcp.gnmap" ]]; then
    grep '/open/' "$OUT/full_tcp.gnmap" | while read -r line; do
      ip=$(awk '{print $2}' <<<"$line")
      ports=$(grep -oE '[0-9]+/open' <<<"$line" | cut -d/ -f1 | paste -sd, -)
      [[ -n "$ports" ]] && echo "$ip $ports"
    done
  elif [[ -f "$OUT/masscan.gnmap" ]]; then
    awk '/Ports:/{print}' "$OUT/masscan.gnmap" | while read -r line; do
      ip=$(awk '{print $4}' <<<"$line")
      ports=$(grep -oE '[0-9]+/open' <<<"$line" | cut -d/ -f1 | sort -un | paste -sd, -)
      [[ -n "$ports" ]] && echo "$ip $ports"
    done
  fi
}
build_map | sort -u > "$OUT/host_ports.txt"
ok "Hosts with open TCP ports: $(wc -l < "$OUT/host_ports.txt")"

scan_host() {
  local ip="$1" ports="$2"
  local hd="$OUT/hosts/$ip"; mkdir -p "$hd"
  printf '%s[sCV]%s %s -> %s\n' "$C_DIM" "$C_RST" "$ip" "$ports"
  sudo nmap -sCV -Pn -p"$ports" -T"$NMAP_TIMING" \
    --version-intensity 6 "$ip" -oA "$hd/service" >/dev/null 2>&1 || true
}
export -f scan_host; export OUT C_DIM C_RST NMAP_TIMING

log "Service/version + default scripts on open ports (parallel x$THREADS)"
while read -r ip ports; do printf '%s\t%s\n' "$ip" "$ports"; done < "$OUT/host_ports.txt" \
  | xargs -P "$THREADS" -d '\n' -I{} bash -c 'IFS=$'"'"'\t'"'"' read -r ip ports <<<"{}"; scan_host "$ip" "$ports"'

# ---- Phase C: top UDP (slow) ----------------------------------------------
if [[ "$SKIP_UDP" != "true" ]]; then
  log "Top-100 UDP scan (SNMP/DNS/NetBIOS/etc.)"
  run "$LOG" sudo nmap -sU --top-ports 100 --open --min-rate "$((MIN_RATE/2))" \
    -iL "$LIVE" -oA "$OUT/udp_top" || true
fi

# ---- Phase D: classify hosts into role buckets for downstream modules -----
phase "Role classification (from service scans)"
classify() {
  local pat="$1" outfile="$2"
  grep -rilE "$pat" "$OUT/hosts"/*/service.nmap 2>/dev/null \
    | sed 's#.*/hosts/##; s#/service.nmap##' | sort -u > "$RUN/$outfile"
}
classify 'microsoft-ds|netbios-ssn|port 445'                "hosts_smb.txt"
classify 'ldap|kerberos-sec|port 88|microsoft-ds.*Active'   "hosts_dc.txt"
classify 'http|https|ssl/http'                              "hosts_web.txt"
classify 'ms-sql|mysql|postgresql|oracle|mongodb'           "hosts_db.txt"
classify 'ms-wbt-server|rdp|port 3389'                      "hosts_rdp.txt"
classify 'winrm|wsman|port 5985'                            "hosts_winrm.txt"

for f in hosts_smb hosts_dc hosts_web hosts_db hosts_rdp hosts_winrm; do
  n=$( [[ -f "$RUN/$f.txt" ]] && wc -l < "$RUN/$f.txt" || echo 0 )
  ok "$(printf '%-12s' "$f"): $n hosts"
done

# Build a web URL list (http/https) for the web module.
: > "$RUN/web_urls.txt"
for nmapf in "$OUT"/hosts/*/service.nmap; do
  ip=$(basename "$(dirname "$nmapf")")
  grep -E '^[0-9]+/tcp +open' "$nmapf" 2>/dev/null | while read -r line; do
    port=$(cut -d/ -f1 <<<"$line")
    if grep -qiE 'https|ssl/http' <<<"$line"; then echo "https://$ip:$port"
    elif grep -qiE 'http' <<<"$line";       then echo "http://$ip:$port"; fi
  done
done | sort -u >> "$RUN/web_urls.txt"
ok "Web URLs: $(wc -l < "$RUN/web_urls.txt") -> $RUN/web_urls.txt"
