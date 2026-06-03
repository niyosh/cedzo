#!/usr/bin/env bash
# ==========================================================================
# 05-enum-db.sh  -  Enumerate MSSQL / MySQL / PostgreSQL / Oracle / Mongo.
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh
RUN="${RUN:?RUN not set}"
OUT="$RUN/05-db"; mkdir -p "$OUT"; LOG="$OUT/db.log"
DBH="$RUN/hosts_db.txt"
task_listing || [[ -s "$DBH" ]] || { warn "No DB hosts found. Skipping."; exit 0; }

phase "Database Enumeration"
NXC=$(nxc_bin) || NXC=""

# ---- Sub-task: DB-specific NSE characterisation ---------------------------
# NOTE: brute-force scripts (e.g. pgsql-brute) are intentionally excluded —
# they risk account lockout. Only info / empty-password / config checks run.
t_nse() {
  log "DB-focused NSE scripts (info / empty-password / config checks)"
  run "$LOG" sudo nmap -Pn -sV \
    -p 1433,1521,3306,5432,6379,9200,27017 \
    --script "ms-sql-info,ms-sql-empty-password,ms-sql-config,mysql-info,mysql-empty-password,mysql-users,mongodb-info,oracle-tns-version,redis-info" \
    -iL "$DBH" -oA "$OUT/db_nse" 2>/dev/null || true
}

# ---- Sub-task: MSSQL probe via netexec (null + provided creds) ------------
t_mssql() {
  [[ -n "$NXC" ]] || { warn "netexec missing — skipping MSSQL probe."; return 0; }
  log "MSSQL probe (nxc) — null + provided creds"
  run "$LOG" "$NXC" mssql "$DBH" || true
  if [[ -n "$USERNAME" ]]; then
    local CRED=(-u "$USERNAME"); [[ -n "$NTHASH" ]] && CRED+=(-H "$NTHASH") || CRED+=(-p "$PASSWORD")
    run "$LOG" "$NXC" mssql "$DBH" "${CRED[@]}" --local-auth -q "SELECT @@version;" || true
    run "$LOG" "$NXC" mssql "$DBH" "${CRED[@]}" -q "SELECT name FROM sys.databases;" || true
  fi
}

# ---- Sub-task: default-credential checklist (notes only) ------------------
t_creds_notes() {
  log "Default-credential check notes written to $OUT/default_creds_TODO.txt"
  cat > "$OUT/default_creds_TODO.txt" <<'EOF'
Manual / semi-automated default-credential checks worth running on found DBs:
  MSSQL    sa : (blank) | sa:sa | sa:Password1
  MySQL    root : (blank) | root:root | root:toor
  Postgres postgres:postgres | postgres:(blank)
  Oracle   system:manager | sys:change_on_install | scott:tiger
  Mongo    (no auth by default — try direct connect)
  Redis    (often no auth — redis-cli -h <ip> INFO)

Examples:
  impacket-mssqlclient sa:''@<ip>
  mysql -h <ip> -u root -p''
  psql -h <ip> -U postgres
  redis-cli -h <ip>
  mongosh "mongodb://<ip>:27017"
EOF
  cat "$OUT/default_creds_TODO.txt"
}

task nse         "DB-specific NSE (info/empty-password/config)" t_nse
task mssql       "MSSQL probe via netexec (null + creds)"       t_mssql
task creds_notes "Write default-credential checklist (notes)"   t_creds_notes
run_tasks

ok "DB enumeration complete -> $OUT"
