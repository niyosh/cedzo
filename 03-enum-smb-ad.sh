#!/usr/bin/env bash
# ==========================================================================
# 03-enum-smb-ad.sh  -  SMB / NetBIOS / LDAP / Kerberos enumeration.
# Unauthenticated by default; uses creds from config.sh if present.
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh
RUN="${RUN:?RUN not set}"
OUT="$RUN/03-smb-ad"; mkdir -p "$OUT"; LOG="$OUT/smb.log"
SMB="$RUN/hosts_smb.txt"; DC="$RUN/hosts_dc.txt"

phase "SMB / AD Enumeration"
NXC=$(nxc_bin) || { warn "netexec/crackmapexec not found — SMB enum limited."; NXC=""; }

# Build auth args once.
AUTH=(-u "${USERNAME:-}" )
if   [[ -n "$NTHASH"   ]]; then AUTH+=( -H "$NTHASH" )
elif [[ -n "$PASSWORD" ]]; then AUTH+=( -p "$PASSWORD" )
else                            AUTH=(-u '' -p ''); fi   # null session
[[ -n "$USERNAME" ]] && ok "Using credentials: ${DOMAIN:+$DOMAIN\\}$USERNAME" \
                     || log "No creds set — attempting null/guest sessions."

if [[ -n "$NXC" && -s "$SMB" ]]; then
  log "SMB host info, signing status, OS/domain (nxc)"
  run "$LOG" "$NXC" smb "$SMB"                                 # banner: OS, signing, domain
  log "Enumerate shares"
  run "$LOG" "$NXC" smb "$SMB" "${AUTH[@]}" --shares -o "$OUT/shares"
  log "Enumerate users / password policy / RID brute"
  run "$LOG" "$NXC" smb "$SMB" "${AUTH[@]}" --users    | tee "$OUT/users.txt"
  run "$LOG" "$NXC" smb "$SMB" "${AUTH[@]}" --pass-pol
  run "$LOG" "$NXC" smb "$SMB" "${AUTH[@]}" --rid-brute 4000 | tee "$OUT/rid_brute.txt"
  log "Loggable spider of readable shares for interesting files"
  run "$LOG" "$NXC" smb "$SMB" "${AUTH[@]}" -M spider_plus 2>/dev/null || true
fi

# Per-host deep enum with enum4linux-ng (rich on null/guest).
if have enum4linux-ng && [[ -s "$SMB" ]]; then
  enum_host() {
    local ip="$1"
    enum4linux-ng -A -oJ "$OUT/e4l_$ip" "$ip" >"$OUT/e4l_$ip.txt" 2>&1 || true
    printf '%s[+]%s enum4linux-ng %s done\n' "$C_GRN" "$C_RST" "$ip"
  }
  export -f enum_host; export OUT C_GRN C_RST
  log "enum4linux-ng per host (parallel)"
  parallelize enum_host < "$SMB"
fi

# Pull a clean username list from RID brute for AS-REP / Kerberoast collection later.
if [[ -f "$OUT/rid_brute.txt" ]]; then
  grep -oP '(?<=\\)[A-Za-z0-9._-]+(?= \(SidTypeUser\))' "$OUT/rid_brute.txt" \
    | sort -u > "$RUN/domain_users.txt" || true
  [[ -s "$RUN/domain_users.txt" ]] && ok "Harvested $(wc -l <"$RUN/domain_users.txt") users -> domain_users.txt"
fi

# ---- LDAP / Kerberos against DCs ------------------------------------------
if [[ -s "$DC" ]]; then
  phase "Domain Controller LDAP enumeration"
  while read -r dc; do
    log "anonymous LDAP rootDSE / naming contexts on $dc"
    run "$LOG" ldapsearch -x -H "ldap://$dc" -s base namingcontexts 2>/dev/null || true
  done < "$DC"

  if [[ -n "$USERNAME" && ( -n "$PASSWORD" || -n "$NTHASH" ) ]] && have ldapdomaindump; then
    log "Authenticated full domain dump (ldapdomaindump)"
    cred="${PASSWORD:-}"; [[ -n "$NTHASH" ]] && cred=":$NTHASH"
    while read -r dc; do
      mkdir -p "$OUT/ldd_$dc"
      run "$LOG" ldapdomaindump -u "$DOMAIN\\$USERNAME" -p "$cred" \
        -o "$OUT/ldd_$dc" "$dc" || true
    done < "$DC"
  fi
fi
ok "SMB/AD enumeration complete -> $OUT"
