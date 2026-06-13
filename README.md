# Recon Kit (CEDZO)

Authorised reconnaissance, end to end, in two modes:

- **internal** — internal-network recon: prep → port/service scan → SMB/AD → web
  → DB → AD recon → vuln detection → reporting → AI client report.
- **external** — external attack-surface recon: prep → OSINT → port/service scan
  → web → exposed-service review → takeover/cloud → vuln detection → reporting →
  AI client report.

You pick the mode when you launch `run.sh` (it asks, or take it as the first
argument). Each mode writes to its own run directory, so the two never collide.

> **Recon-only by design** — with one opt-in exception. Discovery, enumeration,
> fingerprinting, and non-exploitative vulnerability *detection* only — no
> spraying, brute force, relay, or disruptive actions. The **single intrusive
> step** is the OWASP ZAP **active** scan in phase 04, which sends real attack
> payloads (XSS/SQLi/etc.); it is gated behind `ZAP_ACTIVE` (set `ZAP_ACTIVE=false`
> for spider + passive only). Use only against systems you are explicitly
> authorised to test; `run.sh` requires a scope file and an `AUTHORISED`
> confirmation before anything runs.

## Quick start

```bash
# 1) Scope — one target per line (see scope.txt.example)
#    internal: IPs / ranges / CIDRs only
#    external: public IPs / ranges / CIDRs and/or root domains
printf '10.10.10.0/24\n192.168.50.10-50\n' > scope.txt

# 2) Install/verify tooling for the mode you'll run
chmod +x *.sh lib/*.sh && ./00-setup.sh                 # internal toolset
KIT_MODE=external ./00-setup.sh                          # external toolset

# 3) (optional) edit config.sh — threads, wordlists, creds, AI

# 4) Run — mode is the first argument (omit it and run.sh asks). run.sh then
#    asks for a PROJECT name (or pass PROJECT=... in the environment).
./run.sh                          # prompts mode + project, then full chain
./run.sh internal                 # internal full chain (still asks for project)
./run.sh external                 # external full chain
./run.sh internal 01 02 04        # selected phases (forces re-run)
./run.sh external menu            # interactive: pick a phase → a sub-task
KIT_MODE=external PROJECT=acme ./run.sh   # mode + project via environment

# Authenticated AD recon (internal; read-only creds; still no spraying/brute force):
DOMAIN=CORP.LOCAL DC_IP=10.10.10.10 USERNAME=jdoe PASSWORD='Summer2025!' ./run.sh internal 03 06
```

Output is namespaced by project: `reconoutput/<project>/<mode>/`
(e.g. `reconoutput/acme/internal/`). **Runs resume per project** — re-using a
project name skips phases whose `.done-NN` marker is present; a **new** project
name starts a fresh scan from phase 01. Internal and external each get their own
sub-dir, so they resume independently. Naming a phase explicitly re-runs it;
delete the project dir to start that project over.

## Phases

**Internal mode**

| # | Module | What it does |
|---|--------|--------------|
| 01 | prep | Validate scope, check tooling, build `live_hosts.txt` |
| 02 | portscan | Full TCP `-p-` + top-500 UDP (`-Pn`, on by default), `nmap -sCV`, classify by role, build `web_urls.txt` |
| 03 | smb-ad | SMB/shares/RID, GPP cpassword, anon-LDAP, DNS AXFR, NFS |
| 04 | web | httpx/whatweb, gowitness, exposures, wpscan, katana+feroxbuster crawl, nuclei, **OWASP ZAP** (spider + passive + active) |
| 05 | db | MSSQL/MySQL/PostgreSQL/Oracle/Mongo/Redis enum (no brute force) |
| 06 | ad-recon | kerbrute, AS-REP/Kerberoast, BloodHound (optional `BLOODHOUND`), Certipy ADCS, delegation/SCCM, Timeroast |
| 07 | vuln-scan | MS17-010, SMBGhost, BlueKeep, Zerologon, PrintNightmare, PetitPotam, log4j/ProxyShell, TLS, SNMP |
| 08 | report | `REPORT.md` + `nmap_report.html` + `web_report.html` |
| 09 | xlsx-report | **(AI)** zips the run → client `pentest_vulnerability_report.xlsx` (findings + attack chains) |

**External mode**

| # | Module | What it does |
|---|--------|--------------|
| 01 | prep | Validate + classify scope (IP/CIDR vs domain), check tooling, seed `live_hosts.txt` |
| 02 | osint | WHOIS/ASN, DNS records, subdomain enum (subfinder/amass/crt.sh), reverse DNS, SPF/DKIM/DMARC; resolves names → folds public IPs into scope |
| 03 | portscan | Rate-limited full TCP sweep `-p-` (set `TCP_FULL=false` for fast top-ports) + top-500 UDP (`-Pn`, on by default), `nmap -sCV`, role classification, `web_urls.txt`, and `risky_services.txt` |
| 04 | web | httpx/whatweb/favicon, gowitness, exposures, wpscan, vhost, katana+feroxbuster crawl, nuclei (+ AI-targeted pass), **OWASP ZAP** (spider + passive + active) |
| 05 | exposure | Internet-exposed RDP/SSH/VNC/WinRM, databases (info/empty-pass, no brute), FTP/SMB/NFS, edge/VPN appliance + admin-panel fingerprint, SNMP |
| 06 | takeover-cloud | Dangling-CNAME + subdomain-takeover detection, S3/GCS/Azure bucket discovery, exposed `.git`/`.env` repos |
| 07 | vuln-scan | nuclei CVE sweep, edge/VPN appliance CVE checks (Fortinet/Citrix/Pulse/F5/Exchange/…), TLS/SSL audit, SMTP open-relay |
| 08 | report | `REPORT.md` + `nmap_report.html` + `web_report.html` |
| 09 | xlsx-report | **(AI)** archives the run → client `pentest_vulnerability_report.xlsx` (findings + attack chains) |

Scope is authoritative; missing tools are skipped, not fatal. External mode
honours `PASSIVE_ONLY=true` (OSINT + passive sources only, no active scanning).
Regenerate the HTML reports standalone with `reporting/nmap2html.py` /
`nuclei2html.py -i reconoutput/<project>/<mode>`.

See [`FLOWCHART.md`](FLOWCHART.md) for a visual of the pipeline and AI flow.

## AI augmentation (optional)

Each phase can hand its output to an LLM for triage: it ranks/correlates findings
and writes structured analysis to the run dir's `ai/`, phases 04–07 feed earlier
findings forward, and phase 09 turns everything into the client `.xlsx`. The AI
**never scans or exploits** and nothing it returns becomes a command. Off by
default — leave `AI_PROVIDER=none` and the kit behaves exactly as before.

```bash
export AI_PROVIDER=anthropic ANTHROPIC_API_KEY=sk-ant-...   # or one of:
#      AI_PROVIDER=openai    OPENAI_API_KEY=sk-...
#      AI_PROVIDER=gemini    GEMINI_API_KEY=...
#      AI_PROVIDER=ollama    # fully local; run `ollama serve`, no key
./run.sh
```

| Provider | Default `AI_MODEL` | Key var |
|----------|--------------------|---------|
| `anthropic` | `claude-opus-4-8` | `ANTHROPIC_API_KEY` |
| `openai` | `gpt-5.5` | `OPENAI_API_KEY` |
| `gemini` | `gemini-3.5-flash` | `GEMINI_API_KEY` |
| `ollama` | `qwen3:30b-a3b` (256K ctx) | — (local) |

Override with `AI_MODEL` / `AI_BASE_URL`. Defaults are picked for large context +
strict-JSON (the phase-09 digest is ~100K tokens). For **Ollama**, run the
biggest model you can (`qwen3:8b` min, `llama3.3:70b` ideal) and note it silently
caps context at ~4K — the kit sets `num_ctx` via `AI_OLLAMA_NUM_CTX` (default
40960; raise for phase 09 or lower `AI_REPORT_MAX_CHARS`).

**No AI? Manual path.** With no provider, phase 09 still writes the run archive
(`*_results.zip`) + `ai/offline/xlsx-report.prompt.md` under the run dir
(`reconoutput/<project>/<mode>/`). Paste that pack into any AI, save its JSON
reply to `<run-dir>/ai/xlsx-report.json`, then re-run phase 09 for the same
project (e.g. `./run.sh internal 09`) to render the spreadsheet.

**Guarantees:** evidence is redacted (`AI_REDACT_SECRETS`) and bounded before
sending — raw hashes and the secrets report are never sent; phase-04 nuclei runs
once, on AI-curated genuine URLs + tags (intersected with discovered URLs,
falling back to the full list); every call is logged to the run dir's
`ai/log/` and output labelled AI-generated triage, not ground truth.
Sending client data to a cloud API needs authorisation — otherwise use Ollama.
Tunables live in `config.sh` under *AI augmentation*.

## OWASP ZAP web scan

Phase 04 ends with a headless **OWASP ZAP** pass over the live web roots, driven
entirely from the CLI (ZAP daemon + REST API — no GUI, no docker). Per target it
runs **spider → passive scan → active scan**, then writes
`04-web/zap/zap_report.html`, `zap_alerts.json`, and a `zap_summary.txt`
risk tally. Needs the `zaproxy` package (`./00-setup.sh` checks for it).

| Var | Default | Meaning |
|-----|---------|---------|
| `ZAP_SCAN` | `true` | master toggle for the ZAP sub-task |
| `ZAP_ACTIVE` | `true` | run the **active** (intrusive) scan; `false` = spider + passive only |
| `ZAP_AJAX_SPIDER` | `false` | also run the AJAX spider (JS apps; needs a browser) |
| `ZAP_MAX_TARGETS` | `10` | cap web roots fed to ZAP (active scan is slow) |
| `ZAP_SPIDER_TIMEOUT` / `ZAP_ACTIVE_TIMEOUT` | `5` / `20` | per-target minute caps |
| `ZAP_PORT` | `8090` | local daemon port (bound to `127.0.0.1`) |

```bash
ZAP_ACTIVE=false ./run.sh external 04     # spider + passive only (safe/baseline)
ZAP_SCAN=false   ./run.sh internal 04     # skip ZAP entirely
```

## Notes

- Tune `THREADS` / `MIN_RATE` / `NMAP_TIMING` **down** on fragile links; `SKIP_UDP=true` for big scopes.
- ZAP active scan is intrusive (sends payloads) and slow — narrow it with `ZAP_MAX_TARGETS` / timeouts, or `ZAP_ACTIVE=false`.
- Collected hashes are for **offline** cracking, out of band (kit never tests them):
  `hashcat -m 13100` Kerberoast · `-m 18200` AS-REP · `-m 31300` Timeroast.
- Credential attacks are out of scope: no spraying, brute force, poisoning/relay, or exploitation.

## Licence

Public domain — see [`LICENSE`](LICENSE).
