# Internal Recon Kit (CEDZO)

Authorised internal-network reconnaissance, end to end:
prep → port/service scan → SMB/AD → web → DB → AD recon → vuln detection →
reporting → AI client report.

> **Recon-only by design.** Discovery, enumeration, fingerprinting, and
> non-exploitative vulnerability *detection* only — no spraying, brute force,
> relay, or disruptive actions. Use only against systems you are explicitly
> authorised to test; `run.sh` requires a scope file and an `AUTHORISED`
> confirmation before anything runs.

## Quick start

```bash
# 1) Scope — one IP / range / CIDR per line
printf '10.10.10.0/24\n192.168.50.10-50\n' > scope.txt

# 2) Install/verify tooling
chmod +x *.sh lib/*.sh && ./00-setup.sh

# 3) (optional) edit config.sh — threads, wordlists, creds, AI

# 4) Run
./run.sh                 # full chain
./run.sh 01 02 04        # selected phases (forces re-run)
./run.sh menu            # interactive: pick a phase → a sub-task

# Authenticated AD recon (read-only creds; still no spraying/brute force):
DOMAIN=CORP.LOCAL DC_IP=10.10.10.10 USERNAME=jdoe PASSWORD='Summer2025!' ./run.sh 03 06
```

Output lands in `loot/run/`. **Runs resume** — finished phases drop a `.done-NN`
marker and are skipped next time; naming a phase explicitly re-runs it; delete
`loot/run/` to start fresh.

## Phases

| # | Module | What it does |
|---|--------|--------------|
| 01 | prep | Validate scope, check tooling, build `live_hosts.txt` |
| 02 | portscan | Full TCP + top UDP, `nmap -sCV`, classify by role, build `web_urls.txt` |
| 03 | smb-ad | SMB/shares/RID, GPP cpassword, anon-LDAP, DNS AXFR, NFS |
| 04 | web | httpx/whatweb, gowitness, katana+feroxbuster crawl, exposures, wpscan, nuclei |
| 05 | db | MSSQL/MySQL/PostgreSQL/Oracle/Mongo/Redis enum (no brute force) |
| 06 | ad-recon | kerbrute, AS-REP/Kerberoast, BloodHound (optional `BLOODHOUND`), Certipy ADCS, delegation/SCCM, Timeroast |
| 07 | vuln-scan | MS17-010, SMBGhost, BlueKeep, Zerologon, PrintNightmare, PetitPotam, log4j/ProxyShell, TLS, SNMP |
| 08 | report | `REPORT.md` + `nmap_report.html` + `web_report.html` |
| 09 | xlsx-report | **(AI)** zips the run → client `pentest_vulnerability_report.xlsx` (findings + attack chains) |

Scope is authoritative; missing tools are skipped, not fatal. Regenerate the
HTML reports standalone with `reporting/nmap2html.py` / `nuclei2html.py -i loot/run`.

## AI augmentation (optional)

Each phase can hand its output to an LLM for triage: it ranks/correlates findings
and writes structured analysis to `loot/run/ai/`, phases 04–07 feed earlier
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

**No AI? Manual path.** With no provider, phase 09 still writes
`loot/run/cedzo_results.zip` + `loot/run/ai/offline/xlsx-report.prompt.md`. Paste
that pack into any AI, save its JSON reply to `loot/run/ai/xlsx-report.json`, then
`./run.sh 09` renders the spreadsheet.

**Guarantees:** evidence is redacted (`AI_REDACT_SECRETS`) and bounded before
sending — raw hashes and the secrets report are never sent; the phase-04 nuclei
pass is additive (never reduces coverage); every call is logged to
`loot/run/ai/log/` and output labelled AI-generated triage, not ground truth.
Sending client data to a cloud API needs authorisation — otherwise use Ollama.
Tunables live in `config.sh` under *AI augmentation*.

## Notes

- Tune `THREADS` / `MIN_RATE` / `NMAP_TIMING` **down** on fragile links; `SKIP_UDP=true` for big scopes.
- Collected hashes are for **offline** cracking, out of band (kit never tests them):
  `hashcat -m 13100` Kerberoast · `-m 18200` AS-REP · `-m 31300` Timeroast.
- Credential attacks are out of scope: no spraying, brute force, poisoning/relay, or exploitation.

## Licence

Public domain — see [`LICENSE`](LICENSE).
