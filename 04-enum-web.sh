#!/usr/bin/env bash
# ==========================================================================
# 04-enum-web.sh  -  Probe, fingerprint, screenshot, content-discover, scan
# all HTTP/S services found in the port scan.
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh
RUN="${RUN:?RUN not set}"
OUT="$RUN/04-web"; mkdir -p "$OUT"; LOG="$OUT/web.log"
URLS="$RUN/web_urls.txt"
[[ -s "$URLS" ]] || { warn "No web URLs (run 02 first). Skipping."; exit 0; }

phase "Web Enumeration ($(wc -l <"$URLS") targets)"

# ---- Probe + fingerprint --------------------------------------------------
# Run httpx for fingerprint detail only (titles, tech, status). We deliberately
# do NOT use httpx to filter the target list: it can silently drop slow-but-live
# services (e.g. Tomcat on 8180), and nmap -sCV already confirmed these ports
# speak HTTP. Trusting nmap keeps every discovered web port in scope.
if have httpx; then
  log "httpx: titles, tech, status, redirects"
  run "$LOG" httpx -silent -l "$URLS" \
    -title -tech-detect -status-code -server -web-server -location -ip \
    -o "$OUT/httpx.txt" || true
fi
cp "$URLS" "$OUT/live_urls.txt"
LIVE_URLS="$OUT/live_urls.txt"

if have whatweb; then
  log "whatweb fingerprint (aggression 3)"
  run "$LOG" whatweb -a3 --no-errors -i "$LIVE_URLS" \
    --log-brief="$OUT/whatweb.txt" || true
fi

# ---- Screenshots ----------------------------------------------------------
if [[ "$SCREENSHOTS" == "true" ]] && have gowitness; then
  log "gowitness screenshots"
  if gowitness scan --help >/dev/null 2>&1; then
    run "$LOG" gowitness scan file -f "$LIVE_URLS" \
      --write-db --screenshot-path "$OUT/screens" 2>/dev/null || true
  else
    run "$LOG" gowitness file -f "$LIVE_URLS" -P "$OUT/screens" 2>/dev/null || true
  fi
  ok "Screenshots -> $OUT/screens"
fi

# ---- Exposure checks (read-only GETs of high-value paths) -----------------
log "Exposure checks (.git/.svn/.env, backups, status, secrets)"
EXPOSE_PATHS=(
  .git/HEAD .git/config .svn/entries .env .DS_Store .htaccess web.config
  config.php.bak config.bak backup.zip backup.tar.gz dump.sql db.sql
  robots.txt sitemap.xml server-status server-info phpinfo.php
  .well-known/security.txt actuator/env actuator/health
)
: > "$OUT/exposures.txt"
while read -r base; do
  [[ -n "$base" ]] || continue
  for pth in "${EXPOSE_PATHS[@]}"; do
    url="${base%/}/$pth"
    code=$(curl -k -s -o /dev/null -m 8 -w '%{http_code}' "$url" 2>/dev/null || echo 000)
    [[ "$code" =~ ^(200|301|302|401|403)$ ]] && printf '%s  %s\n' "$code" "$url" >> "$OUT/exposures.txt"
  done
done < "$LIVE_URLS"
if [[ -s "$OUT/exposures.txt" ]]; then
  sort -u -o "$OUT/exposures.txt" "$OUT/exposures.txt"
  warn "Exposed paths -> $OUT/exposures.txt ($(wc -l <"$OUT/exposures.txt"))"
fi

# ---- Favicon hashing (mmh3 — fingerprint admin panels / products) ---------
if have httpx; then
  log "favicon hashing (mmh3)"
  httpx -silent -l "$LIVE_URLS" -favicon -o "$OUT/favicon.txt" 2>/dev/null || true
fi

# ---- WordPress deep-scan (passive enumeration) ----------------------------
if have wpscan && [[ -s "$OUT/whatweb.txt" ]]; then
  wpurls=$(grep -iE 'wordpress' "$OUT/whatweb.txt" | grep -oE 'https?://[^ ]+' | sort -u || true)
  for u in $wpurls; do
    safe=$(sed 's#[^A-Za-z0-9]#_#g' <<<"$u")
    log "wpscan $u (passive)"
    wpscan --url "$u" --no-banner --no-update --random-user-agent \
      --plugins-detection passive --enumerate vp,vt,cb,dbe \
      -o "$OUT/wpscan_$safe.txt" 2>/dev/null || true
  done
  [[ -n "$wpurls" ]] && ok "WordPress scans -> $OUT/wpscan_*.txt"
fi

# ---- NTLM endpoint recon (leaks internal AD domain/host/OS) ---------------
if have ntlmrecon; then
  log "NTLMRecon (extract internal AD domain/host/OS from NTLM challenges)"
  ntlmrecon --infile "$LIVE_URLS" --outfile "$OUT/ntlmrecon.csv" --output csv 2>/dev/null \
    || while read -r u; do ntlmrecon --input "$u" >> "$OUT/ntlmrecon.txt" 2>/dev/null || true; done < "$LIVE_URLS"
  { [[ -s "$OUT/ntlmrecon.csv" ]] || [[ -s "$OUT/ntlmrecon.txt" ]]; } && ok "NTLM recon -> $OUT/ntlmrecon.*"
fi

# ---- IIS 8.3 short-name disclosure (shortscan) ----------------------------
if have shortscan; then
  log "shortscan (IIS tilde / 8.3 short-name enumeration)"
  while read -r u; do
    shortscan "$u" >> "$OUT/shortscan.txt" 2>/dev/null || true
  done < "$LIVE_URLS"
  grep -iE 'vulnerable|IIS short' "$OUT/shortscan.txt" 2>/dev/null && warn "IIS short-name disclosure -> $OUT/shortscan.txt" || true
fi

# ---- CMS enumeration (optional, CMSeeK) -----------------------------------
if [[ "${WEB_CMS:-false}" == "true" ]] && have cmseek; then
  log "CMSeeK CMS enumeration"
  while read -r u; do
    cmseek -u "$u" --batch >> "$OUT/cmseek.txt" 2>/dev/null || true
  done < "$LIVE_URLS"
  [[ -s "$OUT/cmseek.txt" ]] && ok "CMSeeK -> $OUT/cmseek.txt"
fi

# ---- Virtual-host discovery (optional: needs ffuf + VHOST_WORDLIST) -------
if have ffuf && [[ -n "${VHOST_WORDLIST:-}" && -s "${VHOST_WORDLIST:-/nonexistent}" && -n "${DOMAIN:-}" ]]; then
  log "vhost discovery against ${DOMAIN}"
  while read -r base; do
    host=$(sed -E 's#https?://##; s#/.*##' <<<"$base")
    safe=$(sed 's#[^A-Za-z0-9]#_#g' <<<"$base")
    ffuf -u "$base" -H "Host: FUZZ.${DOMAIN}" -w "$VHOST_WORDLIST" \
      -ac -of csv -o "$OUT/vhost_$safe.csv" 2>/dev/null || true
  done < "$LIVE_URLS"
fi

# ---- Crawl + content discovery (katana + feroxbuster) ---------------------
# Crawl live web roots (katana) and brute-force common paths (feroxbuster),
# then consolidate + de-noise everything into a single prioritised endpoint
# list that is fed to nuclei. All discovery runs BEFORE the vuln scan.
NUCLEI_TARGETS="$LIVE_URLS"
if [[ "${WEB_CRAWL:-true}" == "true" ]]; then
  KATANA_OUT="$OUT/katana.txt"

  # 1) katana crawl (JS-aware)
  if have katana; then
    log "katana crawl (JS-aware, depth ${KATANA_DEPTH:-2})"
    run "$LOG" katana -list "$LIVE_URLS" -jc -d "${KATANA_DEPTH:-2}" -silent \
      -o "$KATANA_OUT" 2>/dev/null || true
  fi

  # 2) feroxbuster content discovery (parallel, capped)
  if have feroxbuster && [[ -s "$WEB_WORDLIST" ]]; then
    ferox_one() {
      local url="$1"
      local safe; safe=$(sed 's#[^A-Za-z0-9]#_#g' <<<"$url")
      feroxbuster -u "$url" -w "$WEB_WORDLIST" -q -k -t 20 \
        -x php,asp,aspx,jsp,html,txt,bak,config \
        --no-recursion -o "$OUT/ferox_$safe.txt" 2>/dev/null || true
      printf '%s[+]%s dirbust %s\n' "$C_GRN" "$C_RST" "$url"
    }
    export -f ferox_one; export OUT WEB_WORDLIST C_GRN C_RST
    log "feroxbuster content discovery (parallel, capped)"
    THREADS_WEB=$(( THREADS<6 ? THREADS : 6 ))   # don't hammer
    xargs -P "$THREADS_WEB" -I{} bash -c 'ferox_one "$@"' _ {} < "$LIVE_URLS"
  fi

  # 3) consolidate katana + feroxbuster output -> de-noise -> nuclei targets
  if have python3; then
    python3 reporting/urlfilter.py "$KATANA_OUT" "$OUT"/ferox_*.txt \
      -o "$OUT/filtered_urls.txt" 2>/dev/null || true
    if [[ -s "$OUT/filtered_urls.txt" ]]; then
      sort -u "$LIVE_URLS" "$OUT/filtered_urls.txt" > "$OUT/nuclei_targets.txt"
      NUCLEI_TARGETS="$OUT/nuclei_targets.txt"
      ok "Consolidated nuclei targets: $(wc -l <"$NUCLEI_TARGETS") (roots + discovered, de-noised)"
    fi
  fi
fi

# ---- Vuln scan ------------------------------------------------------------
if have nuclei; then
  log "nuclei (severity: ${NUCLEI_SEVERITY:-info,low,medium,high,critical})"
  run "$LOG" nuclei -l "$NUCLEI_TARGETS" \
    -severity "${NUCLEI_SEVERITY:-info,low,medium,high,critical}" \
    -timeout "${NUCLEI_TIMEOUT:-10}" -retries 1 \
    -rl 150 -c 25 -o "$OUT/nuclei.txt" -stats 2>/dev/null || true
  ok "nuclei findings: $( [[ -f "$OUT/nuclei.txt" ]] && wc -l <"$OUT/nuclei.txt" || echo 0 )"
fi
ok "Web enumeration complete -> $OUT"
