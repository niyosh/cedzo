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
./run.sh 01 02 04 08

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

Manual, à-la-carte execution. The top level lists the phases (`01`–`09`, with a
`✓` next to completed ones); choosing one lists its sub-tasks, and choosing a
sub-task runs just that step. For example, phase `07` exposes `smb_nse`,
`bluekeep`, `tls`, `snmp`, etc. — pick `bluekeep` to run only that check. `a`
runs a whole phase; the full chain is still `./run.sh` with no arguments.

## Phases

| # | Module | What it does |
|---|--------|--------------|
| 01 | prep | Validate scope, check tooling, build `live_hosts.txt` |
| 02 | portscan | Full TCP + top UDP, `nmap -sCV`, classify hosts by role, build `web_urls.txt` |
| 03 | smb-ad | SMB/shares/RID, GPP cpassword, anon-LDAP dump, DNS AXFR + dnsrecon, NFS exports |
| 04 | web | httpx/whatweb, gowitness, katana + feroxbuster crawl, exposures, favicon, wpscan, nuclei |
| 05 | db | MSSQL/MySQL/PostgreSQL/Oracle/Mongo/Redis enum (no brute force) |
| 06 | ad-recon | kerbrute, AS-REP/Kerberoast, BloodHound (optional, `BLOODHOUND`), Certipy ADCS, LDAP recon, delegation/SCCM enum, Timeroast |
| 07 | vuln-scan | MS17-010, SMBGhost, BlueKeep, Zerologon, PrintNightmare, PetitPotam, log4j/ProxyShell sweep, TLS, SNMP |
| 08 | report | Top-Risks rollup → `REPORT.md` + `nmap_report.html` + `web_report.html` |
| 09 | xlsx-report | **(AI)** archives the run, sends all results to the configured LLM → client `pentest_vulnerability_report.xlsx` (findings register + attack chains) |

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

## AI augmentation (optional)

Every phase can hand its output to an LLM for triage. The AI sits **between**
the tools: it reads a phase's evidence, ranks what matters, correlates across
findings, and writes structured analysis to `loot/run/ai/`. It is a triage
layer only — **the tools stay authoritative, the AI never scans or exploits,
and nothing it returns is turned into a command.**

**Four providers** — pick one with `AI_PROVIDER`; only that provider's key is
needed (Ollama needs none). Leave `AI_PROVIDER=none` (default) and the kit
behaves exactly as before.

```bash
# Anthropic (Claude)
export AI_PROVIDER=anthropic   ANTHROPIC_API_KEY=sk-ant-...

# OpenAI
export AI_PROVIDER=openai      OPENAI_API_KEY=sk-...

# Google Gemini
export AI_PROVIDER=gemini      GEMINI_API_KEY=...

# Ollama (fully local — nothing leaves the box)
export AI_PROVIDER=ollama      # ensure `ollama serve` is running
./run.sh
```

### Recommended models (per CEDZO's workload)

CEDZO needs three things from a model: **large context** (phase 09 ships
~100K tokens of combined evidence in one call), **strong reasoning** (attack-path
synthesis / correlation), and **reliable strict-JSON** output. Defaults below are
chosen to satisfy all three; the "budget" column is fine for the smaller
per-phase calls but may struggle on the phase-09 register.

| Provider | Default (`AI_MODEL`) — recommended | Context | Budget alternative | Key var |
|----------|-----------------------------------|---------|--------------------|---------|
| `anthropic` | `claude-opus-4-8` | 1M | `claude-sonnet-4-6` (1M, cheaper) | `ANTHROPIC_API_KEY` |
| `openai` | `gpt-5.5` | 1M | `gpt-5.4-mini` (400K) | `OPENAI_API_KEY` |
| `gemini` | `gemini-3.5-flash` | 1M | `gemini-2.5-flash` (1M) / `gemini-3.1-pro-preview` (2M, max reasoning) | `GEMINI_API_KEY` |
| `ollama` | `qwen3:30b-a3b` (MoE, 256K ctx) | 256K | `qwen3:14b` / step up to `llama3.3:70b` | — (local) |

> Model lineups move fast — these are current as of June 2026. Override any with
> `AI_MODEL`, and the endpoint with `AI_BASE_URL` (e.g. a remote Ollama box or an
> OpenAI-compatible gateway). Notes: GPT-5.x are reasoning models (the kit sends
> `max_completion_tokens` and lets reasoning default to *medium*); Gemini 2.0
> Flash was retired June 2026 — use 2.5/3.x.

**Local (Ollama) sizing** — structured-output reliability and security reasoning
both scale with size, so run the largest you can. The default `qwen3:30b-a3b` is
a mixture-of-experts model: ~19 GB, 256K context, fast (≈3B active params), and
strong at JSON/tool-calling — the best all-round local pick for CEDZO.

| VRAM / RAM | `AI_MODEL` | Notes |
|------------|-----------|-------|
| 6–8 GB | `qwen3:8b` | works; may drift on the big phase-09 schema |
| 16–24 GB | `qwen3:30b-a3b` *(default)* | MoE, 256K ctx — recommended baseline |
| 24–32 GB | `qwen3:32b` or `gemma3:27b` | dense, strong reasoning |
| 48 GB+ | `llama3.3:70b-instruct` / `qwen3.6:*` | closest to cloud quality locally |

```bash
ollama serve &                 # ensure the daemon is running
ollama pull qwen3:30b-a3b      # then: AI_PROVIDER=ollama ./run.sh
```

**Ollama context gotcha:** Ollama silently caps context at ~4K unless told
otherwise. The kit sets `num_ctx` via `AI_OLLAMA_NUM_CTX` (default 40960). The
per-phase calls fit; for the full phase-09 digest raise it toward `131072` (needs
RAM) **or** lower `AI_REPORT_MAX_CHARS` so the digest fits your context.

Caveat: small local models occasionally drift on the large phase-09 schema — the
kit strips code fences and validates JSON, but if a local run produces no
`pentest_vulnerability_report.xlsx`, step up a model size or use a cloud provider
for the final report only. For the **privacy** reasons below, Ollama is the right
choice when sending client recon data to a cloud API isn't authorised.

What you get per run (under `loot/run/ai/`):

| Phase | AI output |
|-------|-----------|
| 02 portscan | service triage + `priority_hosts.txt` |
| 03 smb-ad | interesting-share / exposure triage |
| 04 web | tech-stack → **nuclei tags**, driving an *additive* `nuclei_ai.txt` pass; URL triage |
| 05 db | database exposure triage |
| 06 ad-recon | plain-English AD attack-surface narrative (hash **counts** only — hashes never sent) |
| 07 vuln-scan | cross-correlated, prioritised detections |
| 08 report | **executive summary** injected into `REPORT.md` (`ai/executive_summary.md`) |
| 09 xlsx-report | archives the run, sends **all** results to the LLM → **client `pentest_vulnerability_report.xlsx`** (severity-ranked findings register + attack-path chains, matching the house template) |

**Compounding analysis (online).** Phases 04–07 feed the *earlier phases'* AI
findings into their own prompt, so the picture builds up: by phase 07 the model
correlates vuln detections against the web/SMB/AD findings already triaged, and
phases 08–09 synthesise across everything.

### No AI configured? Manual / offline path

With `AI_PROVIDER=none` (the default), phase 09 still **archives the run** and
writes a **paste-ready prompt pack** instead of calling an API:

```text
loot/run/cedzo_results.zip              # full run, for your records / handoff
loot/run/ai/offline/xlsx-report.prompt.md   # system + JSON schema + redacted evidence
```

To produce the report by hand:

1. Open `loot/run/ai/offline/xlsx-report.prompt.md` (it's also inside the zip).
2. Paste it into ChatGPT / Claude / Gemini / a local model — it returns JSON.
3. Save that JSON to `loot/run/ai/xlsx-report.json`.
4. Run `./run.sh 09` — it renders `pentest_vulnerability_report.xlsx` from your saved JSON.

The evidence in the pack is already redacted and bounded exactly as it would be
if sent automatically — review it before pasting into any third-party service.

How it behaves, by design:

- **Opt-in & non-fatal.** Off by default; if the API is unreachable the phase
  logs a warning and continues — a phase never fails because of the AI. With no
  provider set you still get the zip + manual prompt pack (above).
- **Additive, never subtractive.** The phase-04 AI nuclei pass adds templates
  for the detected stack; the broad scan is unchanged, and AI-chosen tags are
  sanitised to `[a-z0-9_-]` before they touch the command line.
- **Privacy.** All evidence is bounded and run through a redactor
  (`AI_REDACT_SECRETS=true`) that masks passwords/hashes/keys before sending;
  raw hash files and the noseyparker secrets report are never sent at all. This
  is client data leaving your box — get authorisation to use a cloud API on an
  engagement, or leave it off.
- **Auditable.** Every request/response is logged to `loot/run/ai/log/`, and
  all AI output is clearly labelled `AI-generated` and flagged as triage, not
  ground truth.

Tunables live in `config.sh` under *AI augmentation* (`AI_MODEL`, `AI_EFFORT`,
`AI_MAX_INPUT_CHARS`, `AI_NUCLEI_TAGS`, …). Default model: `claude-opus-4-8`.

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
