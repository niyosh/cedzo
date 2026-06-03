<h1 align="center">🛰️ Internal Recon Kit</h1>

<p align="center">
  <b>Authorised internal-network reconnaissance, end to end.</b><br>
  Preflight → port/service scan → SMB/AD → web crawl+scan → DB → AD recon → vuln detection → prioritised reporting.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Kali%20Linux-557C94?logo=kalilinux&logoColor=white">
  <img src="https://img.shields.io/badge/shell-Bash-4EAA25?logo=gnubash&logoColor=white">
  <img src="https://img.shields.io/badge/reports-Python%203.x-3776AB?logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/engine-nmap%20%7C%20nuclei-red">
  <img src="https://img.shields.io/badge/mode-recon--only-success">
  <img src="https://img.shields.io/badge/license-Unlicense-green">
  <img src="https://img.shields.io/badge/status-active-brightgreen">
</p>

---

> ### ⚠️ Recon-only by design
> Discovery, enumeration, fingerprinting, and **non-exploitative** vulnerability **detection** only.
> It does **not** spray passwords, brute-force credentials, exploit, relay, or run disruptive actions —
> nothing here can lock out an account or take a service down.
>
> 🔐 **Use only against systems you are explicitly authorised to test.** The orchestrator forces a
> scope file and an `AUTHORISED` confirmation before anything runs.

---

## 🧬 Lineage

This project merges two earlier tools into one:

| Source | Contributed |
|--------|-------------|
| 🦴 **`ced`** | The Bash orchestration spine — phased modules, scope/auth gate, broad SMB/AD/DB/vuln coverage |
| 🎨 **`internalcorp`** | The **HTML reporting + risk-scoring engine** (`nmap2html.py`, `nuclei2html.py`) and the **crawl → filter → nuclei** web pipeline |

---

## 🗺️ Flow

```
 scope.txt ─► run.sh ─► [AUTHORISED gate] ─► loot/run/  ($RUN = shared bus, reused across runs)
                                                  │
   00 prep ──────────────────────────────────────┤  scope.txt ─► live_hosts.txt
                                                  │
   02 portscan ───────────────────────────────────┤  masscan/nmap ─► host_ports ─► nmap -sCV
        classify ─► hosts_{smb,dc,web,db,rdp,winrm,nfs}.txt  +  web_urls.txt
                                                  │
        ┌───────────────┬───────────────┬─────────┴──────────┐
        ▼               ▼               ▼                    ▼
   03 SMB/AD/NFS    04 WEB          05 DATABASES         06 AD RECON (RO creds)
   shares, RID,     httpx, crawl,   DB NSE,              AS-REP/Kerberoast,
   GPP cpassword,   exposures,      empty-pass,          Certipy ADCS (ESC1-8),
   anon-LDAP, AXFR, favicon,        nxc mssql            BloodHound
   NFS exports      wpscan, nuclei
        └───────────────┴───────────────┴────────────────────┘
                                                  ▼
   07 VULN DETECT   MS17-010 · SMBGhost · BlueKeep · Zerologon · PrintNightmare ·
                    PetitPotam · log4j/ProxyShell sweep · TLS · SNMP walk
                                                  ▼   (fan-in: reads all of $RUN)
   08 REPORT ─► Top-Risks rollup ─► REPORT.md + nmap_report.html + web_report.html
```

---

## 📦 Layout

```text
cedzo/
├── config.sh            # ⚙️  EDIT: scope, creds, threads, wordlists, crawl, flags
├── run.sh               # ▶️  orchestrator (start here)
├── lib/common.sh        # 🧰  logging + helpers (sourced by all)
├── 00-setup.sh          # 🔧  verify/install tooling (nmap, nuclei, katana, certipy…)
├── 00-prep.sh           # ✅  preflight: validate scope → live_hosts.txt
├── 02-portscan.sh       # 📡  full TCP + top UDP, -sCV, role classification (+NFS)
├── 03-enum-smb-ad.sh    # 🪟  SMB/LDAP/shares/RID, GPP cpassword,
│                        #      anon-LDAP dump, DNS AXFR + dnsrecon, NFS export enum
├── 04-enum-web.sh       # 🌐  httpx, whatweb, gowitness, katana+feroxbuster, nuclei,
│                        #      exposures, favicon, wpscan, NTLMRecon, shortscan
├── 05-enum-db.sh        # 🗄️   MSSQL/MySQL/PG/Oracle/Mongo/Redis enum (no brute)
├── 06-ad-recon.sh       # 🎫  kerbrute, AS-REP/Kerberoast, BloodHound, Certipy, LDAP recon,
│                        #      delegation/SCCM enum, Timeroast, ldeep (linWinPwn-derived, read-only)
├── 07-vuln-scan.sh      # 💥  MS17-010, SMBGhost, BlueKeep, Zerologon, PrintNightmare,
│                        #      PetitPotam, log4j/proxyshell sweep, testssl.sh, SNMP walk
├── 08-report.sh         # 📊  noseyparker secrets + Top-Risks rollup + REPORT.md + HTML
├── reporting/
│   ├── urlfilter.py     # 🧹  consolidate + de-noise crawled URLs → nuclei targets
│   ├── nmap2html.py     # 🖥️   infrastructure intel report (risk scoring)
│   └── nuclei2html.py   # 🐛  web vulnerability report (severity-ranked)
└── vendor/
    └── linWinPwn/       # 📦  vendored 3rd-party AD framework (lefayjey) — reference/manual
                         #      use only; cedzo re-implements its READ-ONLY recon in phase 06
```

> Scope is authoritative: every IP/CIDR in `scope.txt` is treated as live and scanned;
> nothing outside it is touched. Host discovery is **not** used to gate targets.

> **linWinPwn:** the full framework is vendored under `vendor/linWinPwn/` for
> reference/manual use. cedzo does **not** run its attack paths — it natively
> re-implements only linWinPwn's read-only enumeration (LDAP recon, delegation,
> SCCM, Timeroast, ldeep) as recon-safe sub-tasks in `06-ad-recon.sh`. See
> [`vendor/linWinPwn/README.md`](vendor/linWinPwn/README.md).

---

## 🎯 Coverage at a glance

| Area | Checks &nbsp;·&nbsp; *(all read-only / non-exploitative)* |
|------|------------------------------------------------------------|
| 🎫 **Active Directory** | RID-brute user harvest, password policy, anonymous LDAP dump, **GPP cpassword (SYSVOL)**, **DNS AXFR + dnsrecon**, **kerbrute userenum** (validate users, no spray), AS-REP/Kerberoast collection, BloodHound, **ADCS template misconfigs (Certipy, ESC1–ESC8)**, **LDAP recon (DC-list, MachineAccountQuota, subnets, password-not-required, passwords in descriptions)**, **delegation enum (unconstrained/constrained/RBCD)**, **SCCM/MECM discovery**, **Timeroast** (offline), **ldeep full LDAP dump** |
| 📁 **File services** | SMB share enumeration, **NFS exports** + read-only top-level listing |
| 🌐 **Web** | httpx/whatweb fingerprint, gowitness, katana crawl + feroxbuster, **exposure checks (.git/.svn/.env/backups/status)**, **favicon mmh3 hash**, **WordPress deep-scan**, **NTLMRecon** (internal AD leak), **shortscan** (IIS 8.3), CMSeeK *(opt)*, nuclei |
| 💥 **Vulns (detect)** | MS17-010, **SMBGhost**, **BlueKeep**, Zerologon, PrintNightmare, PetitPotam, **log4j / ProxyShell / ProxyLogon / Spring4Shell sweep**, SMB signing, **TLS hygiene (testssl.sh)**, **SNMP default-community + walk** |
| 🗄️ **Databases** | version / empty-password / config NSE for MSSQL · MySQL · PostgreSQL · Oracle · Mongo · Redis |
| 🔑 **Secrets** | **noseyparker** secret-scan over all collected loot (exposures, AXFR/LDAP dumps, NFS listings) |
| 📊 **Reporting** | **prioritised Top-Risks rollup (finding IDs + severity)**, Markdown report, HTML infra + web reports |

---

## 🚀 Quick start

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

# 4) Run the full unauthenticated recon chain
./run.sh

# …or selected phases only (forces them to re-run)
./run.sh 00 02 04 08

# …or drive it manually: pick a phase (00–08), then a single sub-task to run
./run.sh menu

# 🔑 Authenticated AD recon (read-only creds → LDAP dump, BloodHound, ADCS,
#    SPN + AS-REP collection — still no spraying or brute force):
DOMAIN=CORP.LOCAL DC_IP=10.10.10.10 USERNAME=jdoe PASSWORD='Summer2025!' ./run.sh 03 06
```

> **Output is a fixed directory (`loot/run/`) and runs resume.** Each phase that
> finishes drops a `.done-NN` marker; the next `./run.sh` skips completed phases
> and picks up at the first unfinished one (e.g. if 00/02/03 are done, it starts
> at 04). Naming phases explicitly (`./run.sh 04`) forces them to re-run; delete
> `loot/run/` to start completely fresh.

### 🧭 Interactive menu (`./run.sh menu`)

Manual, à-la-carte execution. The top level lists the phases (`00`–`08`, with a
`✓` next to completed ones); choosing one lists its **sub-tasks**, and choosing a
sub-task runs just that step. For example, phase `07` exposes `smb_nse`,
`nxc_modules`, `zerologon`, `smbghost`, `bluekeep`, `nuclei_cve`, `tls`, `snmp` —
pick `bluekeep` to run only the BlueKeep check. `a` runs a whole phase; the full
chain is still `./run.sh` with no arguments.

---

## 🌐 Web pipeline

Phase 04 crawls discovered web roots with **katana** (JS-aware) and brute-forces paths with
**feroxbuster**, then `reporting/urlfilter.py` **consolidates and de-noises** everything before nuclei:

- ✅ keeps interesting endpoints (good status codes, parameters, admin/login paths, dynamic extensions)
- 🧹 drops static assets, Apache autoindex sort links, doc/templated placeholder URLs, bare relatives
- 🔁 collapses param-value duplicates by `(host, path, param-names)` so `index.php?page=a/b/c…` → one target

The prioritised endpoints are added to the nuclei target set — nuclei scans **real application paths**,
not just bare web roots.

```bash
# config.sh
WEB_CRAWL=true                         # set false to scan web roots only
KATANA_DEPTH=2                         # raise for deeper SPAs
NUCLEI_SEVERITY="info,low,medium,high,critical"   # drop "info," for speed/signal
NUCLEI_TIMEOUT=10                      # per-request timeout (guards fragile hosts)
```

---

## 📊 Reports

Phase 08 writes three artefacts into the run directory:

| File | What it is |
|------|------------|
| 📝 `REPORT.md` | Consolidated Markdown — **Top-Risks rollup** (`RK-001…`), asset counts, hosts by role, all findings |
| 🖥️ `nmap_report.html` | Infrastructure intelligence: per-host services, **risk score**, derived findings (legacy protocols, weak crypto, exposed DBs, NSE signals) |
| 🐛 `web_report.html` | Web vulnerabilities from nuclei, deduped and **severity-ranked** per host |

Regenerate the HTML standalone against any run dir (stdlib-only, no `pip install`):

```bash
python3 reporting/nmap2html.py   -i loot/run-<ts> -o nmap_report.html
python3 reporting/nuclei2html.py -i loot/run-<ts> -o web_report.html
```

---

## 🧭 Asset-to-module map

| Asset in scope | Primary modules | What you get |
|----------------|-----------------|--------------|
| 🎫 Domain Controllers | 03 · 06 · 07 | LDAP dump + recon (MAQ, subnets, delegation, SCCM, desc passwords), AXFR, roastable accounts, Timeroast, ADCS (ESCx), Zerologon/PetitPotam, BloodHound |
| 📁 File servers | 03 | Share enumeration, NFS exports |
| 🌐 Web / app servers | 04 | Fingerprint, crawl + feroxbuster, exposures, favicon, wpscan, nuclei, screenshots |
| 🗄️ Database servers | 05 | Version / empty-password / config checks (no brute force) |
| 🖥️ Terminal / RDP / WinRM | 02 · 07 | Exposed management surfaces, BlueKeep check |
| 🧱 Hyper-V host | 02 · 03 · 07 | SMB/WinRM surface, vuln detection |
| 🛰️ Switches / endpoints | 02 · 07 | SNMP default communities + walk, mgmt interfaces |

---

## 🔁 Output & follow-up

Everything lands in `loot/run-<timestamp>/`. Start with the **Top-Risks** table in `REPORT.md`,
then drill into evidence. Any hashes collected during AD recon are for **offline** cracking,
out of band on your own hardware — the kit never tests them against the domain:

```bash
hashcat -m 13100 kerberoast_hashes.txt rockyou.txt   # Kerberoast (TGS)
hashcat -m 18200 asrep_hashes.txt      rockyou.txt   # AS-REP
```

Import the BloodHound zip into the GUI to map attack paths; feed Certipy output to your ADCS notes.

---

## 📝 Notes

- 🧩 Modules **degrade gracefully** — a missing tool is skipped, not fatal.
- 🐢 Tune `THREADS`, `MIN_RATE`, `NMAP_TIMING` **down** on fragile / segmented links.
- ⏭️ `SKIP_UDP=true` for big scopes where UDP scanning is too slow.
- 🚫 Credential **attacks** are intentionally out of scope: no spraying, no brute force,
  no LLMNR/NBT-NS poisoning or relay, no exploitation. Run such tooling manually,
  separately, only when your RoE explicitly permits.

---

## 📄 Licence

Released into the public domain — see [`LICENSE`](LICENSE).

<p align="center"><sub>Built for authorised security assessments. Use responsibly.</sub></p>
