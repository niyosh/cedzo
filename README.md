# Internal Recon Kit

Authorised internal-network reconnaissance, end to end:
preflight → port/service scan → SMB/AD → web crawl+scan → DB → AD recon →
vuln detection → prioritised reporting.

> **Recon-only by design.** Discovery, enumeration, fingerprinting, and
> non-exploitative vulnerability *detection* only. It does not spray passwords,
> brute-force credentials, exploit, relay, or run disruptive actions — nothing
> here can lock out an account or take a service down.
>
> Use only against systems you are explicitly authorised to test. The
> orchestrator requires a scope file and an `AUTHORISED` confirmation before
> anything runs.

## Quick start

```bash
# 1) Define scope — one IP / range / CIDR per line
cat > scope.txt <<'EOF'
10.10.10.0/24
192.168.50.10-50
EOF

# 2) Check tooling (offers to install anything missing)
chmod +x *.sh lib/*.sh
./00-setup.sh

# 3) Edit config.sh (threads, wordlists, crawl depth; optionally add read-only creds)

# 4) Run the full recon chain
./run.sh

# …or selected phases only (forces them to re-run)
./run.sh 00 02 04 08

# …or drive it manually: pick a phase, then a single sub-task
./run.sh menu

# Authenticated AD recon (read-only creds — still no spraying or brute force):
DOMAIN=CORP.LOCAL DC_IP=10.10.10.10 USERNAME=jdoe PASSWORD='Summer2025!' ./run.sh 03 06
```

Output goes to a fixed directory, `loot/run/`, and **runs resume**: each phase
that finishes drops a `.done-NN` marker, so the next `./run.sh` skips completed
phases and picks up at the first unfinished one. Naming phases explicitly
(`./run.sh 04`) forces them to re-run; delete `loot/run/` to start fresh.

## Interactive menu (`./run.sh menu`)

Manual, à-la-carte execution. The top level lists the phases (`00`–`08`, with a
`✓` next to completed ones); choosing one lists its sub-tasks, and choosing a
sub-task runs just that step. For example, phase `07` exposes `smb_nse`,
`bluekeep`, `tls`, `snmp`, etc. — pick `bluekeep` to run only that check. `a`
runs a whole phase; the full chain is still `./run.sh` with no arguments.

## Phases

| # | Module | What it does |
|---|--------|--------------|
| 00 | prep | Validate scope, check tooling, build `live_hosts.txt` |
| 02 | portscan | Full TCP + top UDP, `nmap -sCV`, classify hosts by role, build `web_urls.txt` |
| 03 | smb-ad | SMB/shares/RID, GPP cpassword, anon-LDAP dump, DNS AXFR + dnsrecon, NFS exports |
| 04 | web | httpx/whatweb, gowitness, katana + feroxbuster crawl, exposures, favicon, wpscan, nuclei |
| 05 | db | MSSQL/MySQL/PostgreSQL/Oracle/Mongo/Redis enum (no brute force) |
| 06 | ad-recon | kerbrute, AS-REP/Kerberoast, BloodHound, Certipy ADCS, LDAP recon, delegation/SCCM enum, Timeroast, ldeep |
| 07 | vuln-scan | MS17-010, SMBGhost, BlueKeep, Zerologon, PrintNightmare, PetitPotam, log4j/ProxyShell sweep, TLS, SNMP |
| 08 | report | Top-Risks rollup → `REPORT.md` + `nmap_report.html` + `web_report.html` |

Scope is authoritative: every IP/CIDR in `scope.txt` is treated as live and
scanned; nothing outside it is touched. Modules degrade gracefully — a missing
tool is skipped, not fatal.

## Reports

Phase 08 writes three artefacts into the run directory:

- `REPORT.md` — consolidated Markdown: Top-Risks rollup (`RK-001…`), asset
  counts, hosts by role, all findings.
- `nmap_report.html` — infrastructure intel: per-host services, risk score,
  derived findings.
- `web_report.html` — nuclei web findings, deduped and severity-ranked.

Regenerate the HTML standalone against any run dir (stdlib-only):

```bash
python3 reporting/nmap2html.py   -i loot/run -o nmap_report.html
python3 reporting/nuclei2html.py -i loot/run -o web_report.html
```

## linWinPwn (vendored)

The full [linWinPwn](https://github.com/lefayjey/linWinPwn) framework (by
lefayjey) is vendored under `vendor/linWinPwn/` for reference / manual use.
cedzo does **not** run its attack paths — it natively re-implements only
linWinPwn's read-only enumeration (LDAP recon, delegation, SCCM, Timeroast,
ldeep) as recon-safe sub-tasks in `06-ad-recon.sh`. See
[`vendor/linWinPwn/README.md`](vendor/linWinPwn/README.md).

## Notes

- Tune `THREADS`, `MIN_RATE`, `NMAP_TIMING` **down** on fragile / segmented links.
- `SKIP_UDP=true` for big scopes where UDP scanning is too slow.
- Collected hashes are for **offline** cracking, out of band — the kit never
  tests them against the domain:

  ```bash
  hashcat -m 13100 kerberoast_hashes.txt rockyou.txt   # Kerberoast
  hashcat -m 18200 asrep_hashes.txt      rockyou.txt   # AS-REP
  hashcat -m 31300 timeroast_hashes.txt  rockyou.txt   # Timeroast
  ```

- Credential **attacks** are intentionally out of scope: no spraying, no brute
  force, no LLMNR/NBT-NS poisoning or relay, no exploitation.

## Licence

Released into the public domain — see [`LICENSE`](LICENSE).
