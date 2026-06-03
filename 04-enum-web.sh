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
LIVE_URLS="$OUT/live_urls.txt"
NUCLEI_TARGETS="$LIVE_URLS"

if ! task_listing; then
  [[ -s "$URLS" ]] || { warn "No web URLs (run 02 first). Skipping."; exit 0; }
  cp "$URLS" "$LIVE_URLS"          # stable target list every sub-task can read
  phase "Web Enumeration ($(wc -l <"$URLS") targets)"
fi

# ---- Sub-task: probe + fingerprint (httpx / whatweb / favicon) ------------
# Run httpx for fingerprint detail only (titles, tech, status). We deliberately
# do NOT use httpx to filter the target list: it can silently drop slow-but-live
# services (e.g. Tomcat on 8180), and nmap -sCV already confirmed these ports
# speak HTTP. Trusting nmap keeps every discovered web port in scope.
t_fingerprint() {
  if have httpx; then
    log "httpx: titles, tech, status, redirects"
    run "$LOG" httpx -silent -l "$URLS" \
      -title -tech-detect -status-code -server -web-server -location -ip \
      -o "$OUT/httpx.txt" || true
  fi
  if have whatweb; then
    log "whatweb fingerprint (aggression 3)"
    run "$LOG" whatweb -a3 --no-errors -i "$LIVE_URLS" \
      --log-brief="$OUT/whatweb.txt" || true
  fi
  if have httpx; then
    log "favicon hashing (mmh3)"
    httpx -silent -l "$LIVE_URLS" -favicon -o "$OUT/favicon.txt" 2>/dev/null || true
  fi
}

# ---- Sub-task: screenshots (gowitness) ------------------------------------
t_screenshots() {
  [[ "$SCREENSHOTS" == "true" ]] && have gowitness || { warn "Screenshots disabled or gowitness missing — skipping."; return 0; }
  log "gowitness screenshots"
  if gowitness scan --help >/dev/null 2>&1; then
    run "$LOG" gowitness scan file -f "$LIVE_URLS" \
      --write-db --screenshot-path "$OUT/screens" 2>/dev/null || true
  else
    run "$LOG" gowitness file -f "$LIVE_URLS" -P "$OUT/screens" 2>/dev/null || true
  fi
  ok "Screenshots -> $OUT/screens"
}

# ---- Sub-task: exposure checks (read-only GETs of high-value paths) -------
t_exposures() {
  log "Exposure checks (.git/.svn/.env, backups, status, secrets)"
  local EXPOSE_PATHS=(
    .git/HEAD .git/config .svn/entries .env .DS_Store .htaccess web.config
    config.php.bak config.bak backup.zip backup.tar.gz dump.sql db.sql
    robots.txt sitemap.xml server-status server-info phpinfo.php
    .well-known/security.txt actuator/env actuator/health
  )
  local base pth url code
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
}

# ---- Sub-task: WordPress deep-scan (passive enumeration) ------------------
t_wpscan() {
  have wpscan && [[ -s "$OUT/whatweb.txt" ]] || { warn "wpscan missing or no whatweb output (run fingerprint first) — skipping."; return 0; }
  local wpurls u safe
  wpurls=$(grep -iE 'wordpress' "$OUT/whatweb.txt" | grep -oE 'https?://[^ ]+' | sort -u || true)
  for u in $wpurls; do
    safe=$(sed 's#[^A-Za-z0-9]#_#g' <<<"$u")
    log "wpscan $u (passive)"
    wpscan --url "$u" --no-banner --no-update --random-user-agent \
      --plugins-detection passive --enumerate vp,vt,cb,dbe \
      -o "$OUT/wpscan_$safe.txt" 2>/dev/null || true
  done
  [[ -n "$wpurls" ]] && ok "WordPress scans -> $OUT/wpscan_*.txt"
}

# ---- Sub-task: NTLM endpoint recon (leaks internal AD domain/host/OS) -----
t_ntlmrecon() {
  have ntlmrecon || { warn "ntlmrecon missing — skipping."; return 0; }
  log "NTLMRecon (extract internal AD domain/host/OS from NTLM challenges)"
  ntlmrecon --infile "$LIVE_URLS" --outfile "$OUT/ntlmrecon.csv" --output csv 2>/dev/null \
    || while read -r u; do ntlmrecon --input "$u" >> "$OUT/ntlmrecon.txt" 2>/dev/null || true; done < "$LIVE_URLS"
  { [[ -s "$OUT/ntlmrecon.csv" ]] || [[ -s "$OUT/ntlmrecon.txt" ]]; } && ok "NTLM recon -> $OUT/ntlmrecon.*"
}

# ---- Sub-task: IIS 8.3 short-name disclosure (shortscan) ------------------
t_shortscan() {
  have shortscan || { warn "shortscan missing — skipping."; return 0; }
  log "shortscan (IIS tilde / 8.3 short-name enumeration)"
  local u
  while read -r u; do
    shortscan "$u" >> "$OUT/shortscan.txt" 2>/dev/null || true
  done < "$LIVE_URLS"
  grep -iE 'vulnerable|IIS short' "$OUT/shortscan.txt" 2>/dev/null && warn "IIS short-name disclosure -> $OUT/shortscan.txt" || true
}

# ---- Sub-task: CMS enumeration (optional, CMSeeK) -------------------------
t_cmseek() {
  [[ "${WEB_CMS:-false}" == "true" ]] && have cmseek || { warn "WEB_CMS disabled or cmseek missing — skipping."; return 0; }
  log "CMSeeK CMS enumeration"
  local u
  while read -r u; do
    cmseek -u "$u" --batch >> "$OUT/cmseek.txt" 2>/dev/null || true
  done < "$LIVE_URLS"
  [[ -s "$OUT/cmseek.txt" ]] && ok "CMSeeK -> $OUT/cmseek.txt"
}

# ---- Sub-task: virtual-host discovery (optional: ffuf + VHOST_WORDLIST) ----
t_vhost() {
  { have ffuf && [[ -n "${VHOST_WORDLIST:-}" && -s "${VHOST_WORDLIST:-/nonexistent}" && -n "${DOMAIN:-}" ]]; } \
    || { warn "ffuf/VHOST_WORDLIST/DOMAIN not all set — skipping vhost discovery."; return 0; }
  log "vhost discovery against ${DOMAIN}"
  local base host safe
  while read -r base; do
    host=$(sed -E 's#https?://##; s#/.*##' <<<"$base")
    safe=$(sed 's#[^A-Za-z0-9]#_#g' <<<"$base")
    ffuf -u "$base" -H "Host: FUZZ.${DOMAIN}" -w "$VHOST_WORDLIST" \
      -ac -of csv -o "$OUT/vhost_$safe.csv" 2>/dev/null || true
  done < "$LIVE_URLS"
}

# ---- Sub-task: crawl + content discovery (katana + feroxbuster) -----------
# Crawl live web roots (katana) and brute-force common paths (feroxbuster),
# then consolidate + de-noise everything into a single prioritised endpoint
# list (nuclei_targets.txt) that the nuclei sub-task feeds on.
t_crawl() {
  [[ "${WEB_CRAWL:-true}" == "true" ]] || { warn "WEB_CRAWL disabled — skipping."; return 0; }
  local KATANA_OUT="$OUT/katana.txt"

  if have katana; then
    log "katana crawl (JS-aware, depth ${KATANA_DEPTH:-2})"
    run "$LOG" katana -list "$LIVE_URLS" -jc -d "${KATANA_DEPTH:-2}" -silent \
      -o "$KATANA_OUT" 2>/dev/null || true
  fi

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
    local THREADS_WEB=$(( THREADS<6 ? THREADS : 6 ))   # don't hammer
    xargs -P "$THREADS_WEB" -I{} bash -c 'ferox_one "$@"' _ {} < "$LIVE_URLS"
  fi

  if have python3; then
    python3 reporting/urlfilter.py "$KATANA_OUT" "$OUT"/ferox_*.txt \
      -o "$OUT/filtered_urls.txt" 2>/dev/null || true
    if [[ -s "$OUT/filtered_urls.txt" ]]; then
      sort -u "$LIVE_URLS" "$OUT/filtered_urls.txt" > "$OUT/nuclei_targets.txt"
      ok "Consolidated nuclei targets: $(wc -l <"$OUT/nuclei_targets.txt") (roots + discovered, de-noised)"
    fi
  fi
}

# ---- Sub-task: vuln scan (nuclei) -----------------------------------------
t_nuclei() {
  have nuclei || { warn "nuclei missing — skipping."; return 0; }
  # Prefer the crawl-consolidated target list if it exists, else the live roots.
  local targets="$LIVE_URLS"
  [[ -s "$OUT/nuclei_targets.txt" ]] && targets="$OUT/nuclei_targets.txt"
  log "nuclei (severity: ${NUCLEI_SEVERITY:-info,low,medium,high,critical}) over $(wc -l <"$targets") targets"
  run "$LOG" nuclei -l "$targets" \
    -severity "${NUCLEI_SEVERITY:-info,low,medium,high,critical}" \
    -timeout "${NUCLEI_TIMEOUT:-10}" -retries 1 \
    -rl 150 -c 25 -o "$OUT/nuclei.txt" -stats 2>/dev/null || true
  ok "nuclei findings: $( [[ -f "$OUT/nuclei.txt" ]] && wc -l <"$OUT/nuclei.txt" || echo 0 )"
}

task fingerprint "Probe + fingerprint (httpx, whatweb, favicon)"      t_fingerprint
task screenshots "Screenshot web roots (gowitness)"                   t_screenshots
task exposures   "Exposure checks (.git/.env/backups/status)"         t_exposures
task wpscan      "WordPress passive deep-scan (wpscan)"               t_wpscan
task ntlmrecon   "NTLM endpoint recon (internal AD info leak)"        t_ntlmrecon
task shortscan   "IIS 8.3 short-name disclosure (shortscan)"          t_shortscan
task cmseek      "CMS enumeration (CMSeeK; needs WEB_CMS=true)"        t_cmseek
task vhost       "Virtual-host discovery (ffuf; needs VHOST_WORDLIST)" t_vhost
task crawl       "Crawl + content discovery -> nuclei_targets.txt"    t_crawl
task nuclei      "Web vuln scan (nuclei)"                             t_nuclei
run_tasks

ok "Web enumeration complete -> $OUT"
