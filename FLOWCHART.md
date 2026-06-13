# CEDZO — Flowchart

Visual overview of the two-mode recon pipeline and the AI augmentation layer.
(Diagrams use [Mermaid](https://mermaid.js.org/); they render on GitHub.)

## 1. Launch, mode & project

```mermaid
flowchart TD
  RUN{{"run.sh"}} --> MODE{"mode?<br/>(arg / KIT_MODE / prompt)"}
  MODE -->|internal| VAL["validate_config<br/>(advisory)"]
  MODE -->|external| VAL
  VAL --> PRJ["project name<br/>(env PROJECT / prompt)"]
  PRJ --> SCOPE["per-project scope<br/>reconoutput/&lt;project&gt;/scope.txt<br/>(seeded once from root scope.txt)"]
  SCOPE --> AUTH{{"AUTHORISED gate"}}
  AUTH --> DIR["run dir<br/>reconoutput/&lt;project&gt;/&lt;mode&gt;/"]
  DIR --> PIPE["phase pipeline 01..09<br/>(resume-aware)"]

  classDef gate fill:#3a1c1c,stroke:#d55,color:#fff;
  class AUTH gate;
```

> **Resume.** A phase that finishes drops `.done-NN`; each sub-task drops
> `.tasks/NN-<id>.done`. Re-running the **same project** skips finished phases,
> and within a partially-done phase resumes at the first unfinished sub-task. A
> **new project name** starts fresh. Internal and external keep separate sub-dirs.

## 2. Recon pipelines (per mode)

```mermaid
flowchart TD
  subgraph INT["internal — network recon"]
    I1["01 prep<br/>→ live_hosts.txt"] --> I2["02 portscan<br/>full TCP + top-500 UDP, -Pn, -sCV"]
    I2 -->|classify| IR["hosts_smb/dc/web/db/rdp/winrm/nfs · web_urls.txt"]
    IR --> I3["03 smb-ad<br/>shares · RID · GPP · anon-LDAP · AXFR · NFS"]
    IR --> I4["04 web<br/>httpx/whatweb · crawl · nuclei"]
    IR --> I5["05 db<br/>DB NSE (no brute force)"]
    IR --> I6["06 ad-recon<br/>roast · ADCS · BloodHound · delegation"]
    IR --> I7["07 vuln-scan<br/>MS17-010 · Zerologon · BlueKeep · TLS · SNMP"]
    I3 & I4 & I5 & I6 & I7 --> I8["08 report"] --> I9["09 xlsx-report"]
    CR["read-only creds (optional, via .env)"] -.-> I3
    CR -.-> I6
  end

  subgraph EXT["external — attack-surface recon"]
    E1["01 prep<br/>classify IP vs domain"] --> E2["02 osint<br/>WHOIS/ASN · subdomains · DNS · SPF/DKIM/DMARC"]
    E2 -->|resolve → fold IPs| E3["03 portscan<br/>full TCP + top-500 UDP, -Pn · risky_services.txt"]
    E3 -->|classify| ER["hosts_web · web_urls.txt"]
    ER --> E4["04 web<br/>httpx/whatweb · crawl · nuclei (+AI pass)"]
    ER --> E5["05 exposure<br/>RDP/SSH/DB/VNC · appliances · panels"]
    E2 --> E6["06 takeover-cloud<br/>dangling CNAME · buckets · exposed repos"]
    E3 --> E7["07 vuln-scan<br/>nuclei CVE · appliance CVE · TLS · SMTP"]
    E4 & E5 & E6 & E7 --> E8["08 report"] --> E9["09 xlsx-report"]
  end

  classDef ai fill:#1c2833,stroke:#5b9bd5,color:#fff;
  class I9,E9 ai;
```

> Recon-only: every phase **reads** scope-derived host lists and **writes**
> evidence files; nothing is exploited.

## 3. AI augmentation layer

```mermaid
flowchart TD
  subgraph PER["per phase (02–07)"]
    EV["phase evidence"] --> RED["redact + bound"]
  end

  RED --> Q{"AI_PROVIDER set<br/>& reachable?"}
  Q -->|yes| API["LLM call<br/>anthropic · openai · gemini · ollama<br/>(structured JSON)"]
  API --> AIJSON["&lt;run&gt;/ai/NN.json + .md"]
  AIJSON -. cross-phase context .-> PER
  Q -->|no| SKIP["skip per-phase analysis"]

  AIJSON --> P8AI["08: executive summary<br/>→ injected into REPORT.md"]

  ALL["all results digest<br/>(REPORT.md + ai/*.json + raw evidence)"] --> R9{"09: AI available?"}
  P8AI --> R9
  R9 -->|yes| GEN["LLM → &lt;run&gt;/ai/xlsx-report.json"]
  R9 -->|no| OFF["*_results.zip<br/>+ ai/offline/xlsx-report.prompt.md"]
  OFF -. paste into any AI, save JSON reply .-> SAVE["&lt;run&gt;/ai/xlsx-report.json"]
  SAVE -->|./run.sh &lt;mode&gt; 09| GEN
  GEN --> XLSX["render<br/>pentest_vulnerability_report.xlsx"]

  classDef out fill:#1c2833,stroke:#5b9bd5,color:#fff;
  class XLSX,OFF out;
```

`<run>` = `reconoutput/<project>/<mode>`.

### Notes

- **Phase 04 feedback:** the web AI curates the genuine target URLs (from the
  katana/dir-enum list) and stack tags, which feed nuclei; with no AI it falls
  back to the full consolidated list.
- **Compounding:** phases 04–07 feed earlier `ai/*.json` back in, so analysis
  builds up; 08–09 synthesise across everything.
- **Privacy:** evidence is redacted + bounded before any send; raw hashes and the
  secrets report are never sent. No provider authorised? Use the offline path
  (zip + prompt pack) or `AI_PROVIDER=ollama` (fully local).
