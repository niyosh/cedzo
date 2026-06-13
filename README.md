# Recon Kit (CEDZO)

Authorised reconnaissance, end to end, in two modes:

- **internal** — internal-network recon: prep → port/service scan → SMB/AD → web
  → DB → AD recon → vuln detection → reporting → AI client report.
- **external** — external attack-surface recon: prep → OSINT → port/service scan
  → web → exposed-service review → takeover/cloud → vuln detection → reporting →
  AI client report.

You pick the mode when you launch `run.sh` (it asks, or take it as the first
argument). Each mode writes to its own run directory, so the two never collide.

> **Recon-only by design.** Discovery, enumeration, fingerprinting, and
> non-exploitative vulnerability *detection* only — no exploitation, spraying,
> brute force, relay, or disruptive actions. Use only against systems you are
> explicitly authorised to test; `run.sh` requires a scope file and an
> `AUTHORISED` confirmation before anything runs.

## Quick start

```bash
# 1) Scope — one target per line (see scope.txt.example)
#    internal: IPs / ranges / CIDRs only
#    external: public IPs / ranges / CIDRs and/or root domains
printf '10.10.10.0/24\n192.168.50.10-50\n' > scope.txt

# 2) Install/verify tooling for the mode you'll run
chmod +x *.sh lib/*.sh && ./00-setup.sh                 # internal toolset
KIT_MODE=external ./00-setup.sh                          # external toolset

# 3) (optional) tunables in config.sh (threads, wordlists, AI); put SECRETS
#    (AD creds, API keys) in .env — it's gitignored and overrides config.sh:
cp .env.example .env && $EDITOR .env

# 4) Run — mode is the first argument (omit it and run.sh asks). run.sh then
#    asks for a PROJECT name (or pass PROJECT=... in the environment).
./run.sh                          # prompts mode + project, then full chain
./run.sh internal                 # internal full chain (still asks for project)
./run.sh external                 # external full chain
./run.sh internal 01 02 04        # selected phases (forces re-run)
./run.sh external menu            # interactive: pick a phase → a sub-task
KIT_MODE=external PROJECT=acme ./run.sh   # mode + project via environment

# Authenticated AD recon (internal; read-only creds in .env or env; no spraying):
DOMAIN=CORP.LOCAL DC_IP=10.10.10.10 USERNAME=jdoe PASSWORD='Summer2025!' ./run.sh internal 03 06
```

Output is namespaced by project: `reconoutput/<project>/<mode>/`
(e.g. `reconoutput/acme/internal/`). Each project keeps its **own** scope at
`reconoutput/<project>/scope.txt` (seeded once from the root `scope.txt`; edit it
per-engagement). **Runs resume per project** — re-using a project name skips
phases whose `.done-NN` marker is present, and within a partially-done phase
resumes at the first unfinished **sub-task** (`.tasks/NN-<id>.done`). A **new**
project name starts fresh from phase 01. Internal and external each get their own
sub-dir, so they resume independently. Naming a phase explicitly re-runs it
cleanly; delete the project dir to start that project over.

## Phases

**Internal mode**

| # | Module | What it does |
|---|--------|--------------|
| 01 | prep | Validate scope, check tooling, build `live_hosts.txt` |
| 02 | portscan | Full TCP `-p-` + top-500 UDP (`-Pn`, on by default), `nmap -sCV`, classify by role, build `web_urls.txt` |
| 03 | smb-ad | SMB/shares/RID, GPP cpassword, anon-LDAP, DNS AXFR, NFS |
| 04 | web | httpx/whatweb, gowitness, exposures, wpscan, katana+feroxbuster crawl, nuclei |
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
| 04 | web | httpx/whatweb/favicon, gowitness, exposures, wpscan, vhost, katana+feroxbuster crawl, nuclei (+ AI-targeted pass) |
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

## Notes

- Tune `THREADS` / `MIN_RATE` / `NMAP_TIMING` **down** on fragile links; `SKIP_UDP=true` for big scopes.
- Collected hashes are for **offline** cracking, out of band (kit never tests them):
  `hashcat -m 13100` Kerberoast · `-m 18200` AS-REP · `-m 31300` Timeroast.
- Credential attacks are out of scope: no spraying, brute force, poisoning/relay, or exploitation.
- Secrets (AD creds, API keys) belong in `.env` (gitignored), not `config.sh`.

## Development

The external tool list has a single source of truth in [`lib/tools.sh`](lib/tools.sh)
(`kit_tools`), consumed by both `00-setup.sh` and the prep-phase checks. Guardrails:

```bash
make check     # syntax (bash -n) + shellcheck + smoke (lists every phase's tasks, both modes)
make lint      # shellcheck only      (skipped with a note if not installed)
make smoke     # phase task-listing only
```

`tools/check.sh` runs the same checks without `make`. Good as a pre-commit hook.

## Licence

Public domain — see [`LICENSE`](LICENSE).
