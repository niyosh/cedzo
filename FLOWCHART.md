# CEDZO — Flowchart

Visual overview of the recon pipeline and the AI augmentation layer.
(Diagrams use [Mermaid](https://mermaid.js.org/); they render on GitHub.)

## 1. Recon pipeline

```mermaid
flowchart TD
  S["scope.txt"] --> RUN{{"run.sh — AUTHORISED gate"}}
  RUN --> P1["01 prep<br/>→ live_hosts.txt"]
  P1 --> P2["02 portscan<br/>nmap -sCV → host_ports · service.nmap"]
  P2 -->|classify by role| ROLES["hosts_smb / dc / web / db / rdp / winrm / nfs<br/>web_urls.txt"]

  ROLES --> P3["03 smb-ad<br/>shares · RID · GPP · anon-LDAP · AXFR · NFS"]
  ROLES --> P4["04 web<br/>httpx/whatweb · crawl · nuclei"]
  ROLES --> P5["05 db<br/>DB NSE (no brute force)"]
  ROLES --> P6["06 ad-recon<br/>roast · ADCS · BloodHound · delegation"]
  ROLES --> P7["07 vuln-scan<br/>MS17-010 · Zerologon · BlueKeep · TLS · SNMP"]

  P3 --> P8
  P4 --> P8
  P5 --> P8
  P6 --> P8
  P7 --> P8["08 report<br/>REPORT.md · nmap_report.html · web_report.html"]
  P8 --> P9["09 xlsx-report<br/>pentest_vulnerability_report.xlsx"]

  CR["read-only creds (optional)"] -.-> P3
  CR -.-> P6

  classDef ai fill:#1c2833,stroke:#5b9bd5,color:#fff;
  class P9 ai;
```

> Recon-only: every phase **reads** scope-derived host lists and **writes**
> evidence files; nothing is exploited. Runs resume via `.done-NN` markers.

## 2. AI augmentation layer

```mermaid
flowchart TD
  subgraph PER["per phase (02–07)"]
    EV["phase evidence"] --> RED["redact + bound"]
  end

  RED --> Q{"AI_PROVIDER set<br/>& reachable?"}
  Q -->|yes| API["LLM call<br/>anthropic · openai · gemini · ollama<br/>(structured JSON)"]
  API --> AIJSON["loot/run/ai/NN.json + .md"]
  AIJSON -. cross-phase context .-> PER
  Q -->|no| SKIP["skip per-phase analysis"]

  AIJSON --> P8AI["08: executive summary<br/>→ injected into REPORT.md"]

  ALL["all results digest<br/>(REPORT.md + ai/*.json + raw evidence)"] --> R9{"09: AI available?"}
  P8AI --> R9
  R9 -->|yes| GEN["LLM → ai/xlsx-report.json"]
  R9 -->|no| OFF["cedzo_results.zip<br/>+ ai/offline/xlsx-report.prompt.md"]
  OFF -. paste into any AI, save JSON reply .-> SAVE["ai/xlsx-report.json"]
  SAVE -->|./run.sh 09| GEN
  GEN --> XLSX["render<br/>pentest_vulnerability_report.xlsx"]

  classDef out fill:#1c2833,stroke:#5b9bd5,color:#fff;
  class XLSX,OFF out;
```

### Notes

- **Phase 04 feedback:** the web AI maps the detected tech stack to nuclei tags
  and runs an *additive* `nuclei_ai.txt` pass — it never replaces the broad scan.
- **Compounding:** phases 04–07 feed earlier `ai/*.json` back in, so analysis
  builds up; 08–09 synthesise across everything.
- **Privacy:** evidence is redacted + bounded before any send; raw hashes and the
  secrets report are never sent. No provider authorised? Use the offline path
  (zip + prompt pack) or `AI_PROVIDER=ollama` (fully local).
