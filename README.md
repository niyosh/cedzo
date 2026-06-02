# Internal Recon Kit

A modular framework for **authorised** internal network reconnaissance, built
for Kali. It chains preflight → port/service scan → SMB/AD enum → web crawl +
scan → DB → AD recon → vuln detection → consolidated reporting, organising all
output into a timestamped run directory and rendering both Markdown and rich
HTML reports.

> This project merges two earlier tools:
> - **`ced`** — the Bash orchestration framework (phased modules, scope/auth
>   gate, broad SMB/AD/DB/vuln coverage). This is the spine.
> - **`internalcorp`** — contributed the **HTML reporting + risk-scoring
>   intelligence engine** (`reporting/nmap2html.py`, `reporting/nuclei2html.py`)
>   and the **katana + dirsearch web-crawl** stage that now enriches the nuclei
>   scan.

> **Recon-only by design.** This kit performs discovery, enumeration,
> fingerprinting, and *non-exploitative* vulnerability **detection**. It does
> **not** spray passwords, brute-force credentials, exploit, or run disruptive
> actions — nothing here can lock out accounts or take a service down.
>
> **Use only against systems you are explicitly authorised to test.** The
> orchestrator forces a scope file and an authorisation confirmation.

## Layout
```
recon-kit/
├── config.sh            # EDIT: scope, creds, threads, wordlists, crawl, flags
├── run.sh               # orchestrator (start here)
├── lib/common.sh        # logging + helpers (sourced by all)
├── 00-setup.sh          # verify/install tooling (incl. katana, certipy, ...)
├── 00-prep.sh           # preflight: validate scope, build live_hosts.txt
├── 02-portscan.sh       # full TCP + top UDP, -sCV, role classification (+NFS)
├── 03-enum-smb-ad.sh    # SMB/LDAP/shares/RID, GPP cpassword, share spider,
│                        #   anon-LDAP dump, DNS AXFR, NFS export enum
├── 04-enum-web.sh       # httpx, whatweb, gowitness, katana+feroxbuster, nuclei,
│                        #   exposure checks (.git/.env), favicon hash, wpscan
├── 05-enum-db.sh        # MSSQL/MySQL/PG/Oracle/Mongo/Redis enum (no brute)
├── 06-ad-recon.sh       # AS-REP/Kerberoast, BloodHound, ADCS/Certipy (RO creds)
├── 07-vuln-scan.sh      # MS17-010, SMBGhost, BlueKeep, Zerologon, PrintNightmare,
│                        #   PetitPotam, log4j/proxyshell sweep, TLS, SNMP walk
├── 08-report.sh         # Top-Risks rollup + REPORT.md + HTML reports
└── reporting/
    ├── urlfilter.py     # merge/prioritise crawled URLs -> nuclei targets
    ├── nmap2html.py     # infrastructure intel report (risk scoring)
    └── nuclei2html.py   # web vulnerability report (severity-ranked)
```

## Coverage at a glance

| Area | Checks (all read-only / non-exploitative) |
|------|--------------------------------------------|
| **Active Directory** | RID-brute user harvest, password policy, anonymous LDAP dump, **GPP cpassword in SYSVOL**, **DNS AXFR**, AS-REP/Kerberoast collection, BloodHound, **ADCS template misconfigs (Certipy, ESC1–ESC8)** |
| **File services** | SMB share enum + **sensitive-file spider** (index only), **NFS exports** + read-only top-level listing |
| **Web** | httpx/whatweb fingerprint, gowitness, katana crawl + feroxbuster, **exposure checks (.git/.svn/.env/backups/status)**, **favicon mmh3 hash**, **WordPress deep-scan**, nuclei |
| **Vulns (detect)** | MS17-010, **SMBGhost**, **BlueKeep**, Zerologon, PrintNightmare, PetitPotam, **log4j/ProxyShell/ProxyLogon/Spring4Shell sweep**, SMB signing, TLS hygiene, **SNMP default-community + walk** |
| **Databases** | version / empty-password / config NSE for MSSQL/MySQL/PG/Oracle/Mongo/Redis |
| **Reporting** | **prioritised Top-Risks rollup (finding IDs + severity)**, Markdown report, HTML infra + web reports |

Scope is authoritative: every IP/CIDR in `scope.txt` is treated as live and
scanned; nothing outside it is touched. Host discovery is not used to gate
targets.

## Quick start
```bash
# 1. Define scope — one IP / range / CIDR per line
cat > scope.txt <<'EOF'
10.10.10.0/24
192.168.50.10-50
EOF

# 2. Check tooling (offers to install missing tools, incl. katana/dirsearch)
chmod +x *.sh lib/*.sh
./00-setup.sh

# 3. Edit config.sh (threads, wordlists, crawl depth; optionally add RO creds)

# 4. Run the full unauthenticated recon chain
./run.sh

# Selected phases only
./run.sh 00 02 04

# Authenticated directory recon (read-only creds enable LDAP dump / BloodHound /
# SPN + AS-REP collection — still no spraying or brute force):
DOMAIN=CORP.LOCAL DC_IP=10.10.10.10 USERNAME=jdoe PASSWORD='Summer2025!' ./run.sh 03 06
```

## Web crawling

Phase 04 now crawls discovered web roots with **katana** (JS-aware) and
content-discovers with **dirsearch**, then `reporting/urlfilter.py` merges and
prioritises the results (good status codes, parameterised endpoints,
admin/login paths, dynamic extensions; static assets and deep-crawl noise are
dropped). The prioritised endpoints are added to the nuclei target set, so
nuclei scans real application paths — not just the bare web roots.

Tune in `config.sh`:
```bash
WEB_CRAWL=true        # set false to skip crawling and scan only web roots
KATANA_DEPTH=2        # raise for deeper single-page apps
```

## Reports

Phase 08 produces three artefacts in the run directory:

| File | What it is |
|------|------------|
| `REPORT.md` | Consolidated Markdown summary (asset counts, hosts by role, findings, AD collection) |
| `nmap_report.html` | Infrastructure intelligence: per-host services, **risk score**, and derived findings (legacy protocols, weak crypto, exposed DBs, NSE signals) |
| `web_report.html` | Web vulnerabilities from nuclei, deduped and **severity-ranked** per host |

You can also regenerate the HTML reports standalone against any run dir:
```bash
python3 reporting/nmap2html.py   -i loot/run-<ts> -o nmap_report.html
python3 reporting/nuclei2html.py -i loot/run-<ts> -o web_report.html
```
The Python reporters use the standard library only — no pip install required.

## Asset-to-module map
| Asset in scope        | Primary modules            | What you get |
|-----------------------|----------------------------|--------------|
| Domain Controllers    | 03, 06, 07                 | LDAP dump, roastable accounts, Zerologon/PetitPotam checks, BloodHound |
| File servers          | 03                         | Share enum, spider for sensitive files |
| Web / app servers     | 04                         | Tech fingerprint, crawl + dirsearch, nuclei, screenshots |
| Database servers      | 05                         | Version / empty-password / config checks (no brute force) |
| Terminal / RDP / WinRM| 02 (classified)            | Exposed management surfaces |
| Hyper-V host          | 02, 03, 07                 | SMB/WinRM surface, vuln detection |
| DHCP server           | 02, 07                     | Service exposure |
| IP switch / endpoints | 02, 07                     | SNMP default communities, mgmt interfaces |

## Output & follow-up
Everything lands in `loot/run-<timestamp>/`. Start with the consolidated
reports, then drill into evidence. Any hashes collected during AD recon are for
**offline** cracking, out of band on your own hardware — the kit never tests
them against the domain:
```bash
hashcat -m 13100 kerberoast_hashes.txt rockyou.txt   # Kerberoast (TGS)
hashcat -m 18200 asrep_hashes.txt      rockyou.txt   # AS-REP
```
Import the BloodHound zip into the GUI to map attack paths.

## Notes
- Modules degrade gracefully if a tool is missing — they skip, not crash.
- Tune `THREADS`, `MIN_RATE`, `NMAP_TIMING` down on fragile/segmented links.
- `SKIP_UDP=true` for big scopes where UDP scanning is too slow.
- Credential **attacks** are intentionally out of scope: no password spraying,
  no brute force, no LLMNR/NBT-NS poisoning or relay, no exploitation. Run any
  such tooling manually, separately, when your RoE explicitly permits.

## Licence
Released into the public domain (Unlicense) — see `LICENSE`.
