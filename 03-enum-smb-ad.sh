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

# ---- Sub-task: SMB host info + share enumeration --------------------------
t_smb_shares() {
  [[ -n "$NXC" && -s "$SMB" ]] || { warn "No netexec or no SMB hosts — skipping."; return 0; }
  log "SMB host info, signing status, OS/domain (nxc)"
  run "$LOG" "$NXC" smb "$SMB"                                 # banner: OS, signing, domain
  log "Enumerate shares"
  run "$LOG" "$NXC" smb "$SMB" "${AUTH[@]}" --shares -o "$OUT/shares"
}

# ---- Sub-task: users / password policy / RID brute -> domain_users --------
t_smb_users() {
  [[ -n "$NXC" && -s "$SMB" ]] || { warn "No netexec or no SMB hosts — skipping."; return 0; }
  log "Enumerate users / password policy / RID brute"
  run "$LOG" "$NXC" smb "$SMB" "${AUTH[@]}" --users    | tee "$OUT/users.txt"
  run "$LOG" "$NXC" smb "$SMB" "${AUTH[@]}" --pass-pol
  run "$LOG" "$NXC" smb "$SMB" "${AUTH[@]}" --rid-brute 4000 | tee "$OUT/rid_brute.txt"
  # Pull a clean username list from RID brute for AS-REP / Kerberoast later.
  if [[ -f "$OUT/rid_brute.txt" ]]; then
    grep -oP '(?<=\\)[A-Za-z0-9._-]+(?= \(SidTypeUser\))' "$OUT/rid_brute.txt" \
      | sort -u > "$RUN/domain_users.txt" || true
    [[ -s "$RUN/domain_users.txt" ]] && ok "Harvested $(wc -l <"$RUN/domain_users.txt") users -> domain_users.txt"
  fi
}

# ---- Sub-task: GPP cpassword / autologin in SYSVOL ------------------------
t_smb_gpp() {
  [[ -n "$NXC" && -s "$SMB" ]] || { warn "No netexec or no SMB hosts — skipping."; return 0; }
  log "GPP cpassword / autologin in SYSVOL (decrypts to plaintext creds)"
  run "$LOG" "$NXC" smb "$SMB" "${AUTH[@]}" -M gpp_password   2>/dev/null | tee -a "$OUT/gpp.txt" || true
  run "$LOG" "$NXC" smb "$SMB" "${AUTH[@]}" -M gpp_autologin  2>/dev/null | tee -a "$OUT/gpp.txt" || true
  grep -iE 'password|cpassword|userName' "$OUT/gpp.txt" 2>/dev/null | grep -viE 'not found|no gpp' \
    | sort -u > "$OUT/gpp_creds.txt" || true
  [[ -s "$OUT/gpp_creds.txt" ]] && warn "GPP credentials recovered -> $OUT/gpp_creds.txt"
}

# ---- Sub-task: per-host deep enum with enum4linux-ng ----------------------
t_enum4linux() {
  have enum4linux-ng && [[ -s "$SMB" ]] || { warn "enum4linux-ng missing or no SMB hosts — skipping."; return 0; }
  enum_host() {
    local ip="$1"
    enum4linux-ng -A -oJ "$OUT/e4l_$ip" "$ip" >"$OUT/e4l_$ip.txt" 2>&1 || true
    printf '%s[+]%s enum4linux-ng %s done\n' "$C_GRN" "$C_RST" "$ip"
  }
  export -f enum_host; export OUT C_GRN C_RST
  log "enum4linux-ng per host (parallel)"
  parallelize enum_host < "$SMB"
}

# ---- Sub-task: LDAP / Kerberos / DNS against DCs --------------------------
t_ldap_dc() {
  [[ -s "$DC" ]] || { warn "No DC hosts — skipping LDAP/DNS enumeration."; return 0; }
  local dc basedn dom cred
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
}

# ---- Sub-task: NFS export enumeration (read-only) -------------------------
t_nfs() {
  local NFS="$RUN/hosts_nfs.txt" ip raw paths exp mp
  { [[ -s "$NFS" ]] && have showmount; } || { warn "No NFS hosts or showmount missing — skipping."; return 0; }
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
}

task smb_shares "SMB host info + share enumeration (nxc)"        t_smb_shares
task smb_users  "Users / password policy / RID brute -> users"  t_smb_users
task smb_gpp    "GPP cpassword / autologin in SYSVOL"            t_smb_gpp
task enum4linux "Per-host enum4linux-ng (parallel)"              t_enum4linux
task ldap_dc    "DC LDAP rootDSE / anon bind / AXFR / dnsrecon"  t_ldap_dc
task nfs        "NFS export enumeration (read-only mount/list)"  t_nfs
run_tasks

ok "SMB/AD enumeration complete -> $OUT"
