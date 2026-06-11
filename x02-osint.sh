#!/usr/bin/env bash
# ==========================================================================
# 02-osint.sh  -  Passive external recon: WHOIS/ASN, DNS records, subdomain
# discovery (subfinder/amass/crt.sh), certificate transparency, reverse DNS,
# and email authentication (SPF/DKIM/DMARC). Resolved hosts are folded back
# into live_hosts.txt so the active phases scan the full footprint.
#
# Passive by default. Active DNS brute is opt-in (AMASS_ACTIVE / DNS_WORDLIST).
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh
RUN="${RUN:?RUN not set}"
OUT="$RUN/02-osint"; mkdir -p "$OUT"; LOG="$OUT/osint.log"
DOMAINS="$RUN/domain_targets.txt"
IPS="$RUN/ip_targets.txt"

phase "OSINT / Passive Recon"

# ---- Sub-task: WHOIS + ASN context ----------------------------------------
t_whois_asn() {
  have whois || { warn "whois missing — skipping WHOIS/ASN."; return 0; }
  : > "$OUT/whois_asn.txt"
  local d ip
  if [[ -s "$DOMAINS" ]]; then
    while read -r d; do
      [[ -n "$d" ]] || continue
      { echo "===== WHOIS (domain): $d ====="; whois "$d" 2>/dev/null \
          | grep -iE 'registrar|registrant|org|name server|creation|expir|updated' | head -30; echo; } \
        >> "$OUT/whois_asn.txt"
    done < "$DOMAINS"
  fi
  if [[ -s "$IPS" ]]; then
    # Single representative IP per scope line (strip CIDR/range) for netblock/ASN.
    while read -r ip; do
      ip=${ip%%/*}; ip=${ip%%-*}
      [[ -n "$ip" ]] || continue
      { echo "===== WHOIS (netblock/ASN): $ip ====="; whois "$ip" 2>/dev/null \
          | grep -iE 'netname|orgname|origin|route|cidr|inetnum|country|aut-num|descr' | head -25; echo; } \
        >> "$OUT/whois_asn.txt"
    done < "$IPS"
  fi
  [[ -s "$OUT/whois_asn.txt" ]] && ok "WHOIS/ASN context -> $OUT/whois_asn.txt"
}

# ---- Sub-task: DNS records ------------------------------------------------
t_dns_records() {
  { have dig && [[ -s "$DOMAINS" ]]; } || { warn "dig missing or no domains — skipping DNS records."; return 0; }
  : > "$OUT/dns_records.txt"
  local d rtype
  while read -r d; do
    [[ -n "$d" ]] || continue
    echo "===== $d =====" >> "$OUT/dns_records.txt"
    for rtype in A AAAA NS MX TXT SOA CNAME CAA; do
      { echo "--- $rtype ---"; dig +short "$d" "$rtype" 2>/dev/null; } >> "$OUT/dns_records.txt"
    done
    echo >> "$OUT/dns_records.txt"
  done < "$DOMAINS"
  ok "DNS records -> $OUT/dns_records.txt"
}

# ---- Sub-task: subdomain discovery (subfinder / amass / crt.sh) -----------
t_subdomains() {
  [[ "${SUBDOMAIN_ENUM:-true}" == "true" && -s "$DOMAINS" ]] \
    || { warn "SUBDOMAIN_ENUM disabled or no domains — skipping."; return 0; }
  : > "$OUT/subdomains.txt"
  local d

  if have subfinder; then
    log "subfinder passive subdomain enum"
    subfinder -dL "$DOMAINS" -silent -all 2>/dev/null >> "$OUT/subdomains.txt" || true
  fi

  if have amass; then
    local amode="-passive"
    [[ "${AMASS_ACTIVE:-false}" == "true" ]] && amode="-active"
    log "amass enum ($amode)"
    while read -r d; do
      [[ -n "$d" ]] || continue
      amass enum $amode -d "$d" -timeout 10 2>/dev/null >> "$OUT/subdomains.txt" || true
    done < "$DOMAINS"
  fi

  # crt.sh certificate-transparency names (no API key; HTTP + jq).
  if [[ "${CT_LOGS:-true}" == "true" ]] && have curl; then
    log "crt.sh certificate-transparency name harvest"
    while read -r d; do
      [[ -n "$d" ]] || continue
      curl -s --max-time 30 "https://crt.sh/?q=%25.$d&output=json" 2>/dev/null \
        | { have jq && jq -r '.[].name_value' 2>/dev/null || grep -oE '[a-zA-Z0-9._-]+\.'"$d"; } \
        | tr 'A-Z' 'a-z' | sed 's/^\*\.//' >> "$OUT/ct_logs.txt" || true
    done < "$DOMAINS"
    [[ -s "$OUT/ct_logs.txt" ]] && { sort -u -o "$OUT/ct_logs.txt" "$OUT/ct_logs.txt"; cat "$OUT/ct_logs.txt" >> "$OUT/subdomains.txt"; }
  fi

  # Active DNS brute (opt-in): dnsx + wordlist over each domain.
  if [[ "${AMASS_ACTIVE:-false}" == "true" || -n "${DNS_WORDLIST:-}" ]] \
     && have dnsx && [[ -s "${DNS_WORDLIST:-/nonexistent}" ]]; then
    log "dnsx DNS brute (wordlist: $DNS_WORDLIST)"
    while read -r d; do
      [[ -n "$d" ]] || continue
      dnsx -silent -d "$d" -w "$DNS_WORDLIST" 2>/dev/null >> "$OUT/subdomains.txt" || true
    done < "$DOMAINS"
  fi

  if [[ -s "$OUT/subdomains.txt" ]]; then
    grep -E '^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$' "$OUT/subdomains.txt" | tr 'A-Z' 'a-z' \
      | sort -u > "$OUT/subdomains.clean" && mv "$OUT/subdomains.clean" "$OUT/subdomains.txt"
    ok "Subdomains discovered: $(_ai_count "$OUT/subdomains.txt") -> $OUT/subdomains.txt"
  else
    warn "No subdomains discovered (or no enumeration tool available)."
  fi
}

# ---- Sub-task: resolve subdomains -> IPs, fold into scope ------------------
t_resolve() {
  [[ "${RESOLVE_SUBDOMAINS:-true}" == "true" ]] || { warn "RESOLVE_SUBDOMAINS disabled — skipping."; return 0; }
  # Resolve subdomains + the root domains themselves.
  local names; names=$(mktemp)
  { [[ -s "$OUT/subdomains.txt" ]] && cat "$OUT/subdomains.txt"; [[ -s "$DOMAINS" ]] && cat "$DOMAINS"; } \
    | sort -u > "$names"
  [[ -s "$names" ]] || { rm -f "$names"; warn "Nothing to resolve — skipping."; return 0; }

  : > "$OUT/resolved.txt"
  if have dnsx; then
    log "dnsx resolve (A records) for $(_ai_count "$names") names"
    dnsx -l "$names" -a -resp-only -silent 2>/dev/null | sort -u > "$OUT/resolved.txt" || true
  elif have dig; then
    log "dig resolve (A records) for $(_ai_count "$names") names"
    local n
    while read -r n; do
      [[ -n "$n" ]] || continue
      dig +short "$n" A 2>/dev/null | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    done < "$names" | sort -u > "$OUT/resolved.txt"
  else
    warn "Neither dnsx nor dig available — cannot resolve."
  fi
  rm -f "$names"

  if [[ -s "$OUT/resolved.txt" ]]; then
    cp "$OUT/resolved.txt" "$RUN/resolved_hosts.txt"
    ok "Resolved public IPs: $(_ai_count "$OUT/resolved.txt") -> $RUN/resolved_hosts.txt"
    # Fold resolved IPs into the active-scan host list (de-duplicated).
    cat "$RUN/live_hosts.txt" "$OUT/resolved.txt" 2>/dev/null \
      | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | sort -u > "$RUN/live_hosts.txt.new" || true
    [[ -s "$RUN/live_hosts.txt.new" ]] && mv "$RUN/live_hosts.txt.new" "$RUN/live_hosts.txt"
    ok "live_hosts.txt now has $(_ai_count "$RUN/live_hosts.txt") host(s) for active scanning."
  fi
}

# ---- Sub-task: reverse DNS over IP targets --------------------------------
t_reverse_dns() {
  have dig || { warn "dig missing — skipping reverse DNS."; return 0; }
  local src="$RUN/live_hosts.txt"
  [[ -s "$src" ]] || { warn "No hosts to reverse-resolve — skipping."; return 0; }
  : > "$OUT/reverse_dns.txt"
  local ip ptr
  while read -r ip; do
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || continue
    ptr=$(dig +short -x "$ip" 2>/dev/null | head -1)
    [[ -n "$ptr" ]] && printf '%s\t%s\n' "$ip" "$ptr" >> "$OUT/reverse_dns.txt"
  done < "$src"
  [[ -s "$OUT/reverse_dns.txt" ]] && ok "Reverse DNS -> $OUT/reverse_dns.txt"
}

# ---- Sub-task: email authentication (SPF / DKIM / DMARC) ------------------
t_email_security() {
  { have dig && [[ -s "$DOMAINS" ]]; } || { warn "dig missing or no domains — skipping email security."; return 0; }
  : > "$OUT/email_security.txt"
  local d spf dmarc sel
  while read -r d; do
    [[ -n "$d" ]] || continue
    echo "===== $d =====" >> "$OUT/email_security.txt"
    spf=$(dig +short TXT "$d" 2>/dev/null | grep -i 'v=spf1' || true)
    dmarc=$(dig +short TXT "_dmarc.$d" 2>/dev/null | grep -i 'v=DMARC1' || true)
    if [[ -n "$spf" ]]; then echo "SPF:   $spf"; else echo "SPF:   *** MISSING (spoofing risk) ***"; fi >> "$OUT/email_security.txt"
    if [[ -n "$dmarc" ]]; then
      echo "DMARC: $dmarc" >> "$OUT/email_security.txt"
      grep -qiE 'p=reject|p=quarantine' <<<"$dmarc" || echo "DMARC: *** policy p=none or weak — minimal protection ***" >> "$OUT/email_security.txt"
    else
      echo "DMARC: *** MISSING (spoofing risk) ***" >> "$OUT/email_security.txt"
    fi
    # Probe common DKIM selectors.
    for sel in default google selector1 selector2 k1 mail smtp dkim; do
      out=$(dig +short TXT "${sel}._domainkey.$d" 2>/dev/null | grep -i 'v=DKIM1' || true)
      [[ -n "$out" ]] && echo "DKIM ($sel): present" >> "$OUT/email_security.txt"
    done
    echo >> "$OUT/email_security.txt"
  done < "$DOMAINS"
  ok "Email authentication review -> $OUT/email_security.txt"
  grep -q 'MISSING' "$OUT/email_security.txt" 2>/dev/null && warn "Weak/missing SPF or DMARC detected (email spoofing risk)."
}

task whois_asn      "WHOIS + ASN / netblock context"               t_whois_asn
task dns_records    "DNS records (A/MX/NS/TXT/SOA/CAA)"             t_dns_records
task subdomains     "Subdomain enum (subfinder/amass/crt.sh)"      t_subdomains
task resolve        "Resolve subdomains -> IPs, fold into scope"   t_resolve
task reverse_dns    "Reverse DNS over target IPs"                  t_reverse_dns
task email_security "Email auth (SPF/DKIM/DMARC) review"           t_email_security
task ai             "AI: triage external footprint"                ai_bridge_02
run_tasks

ok "OSINT complete -> $OUT"
