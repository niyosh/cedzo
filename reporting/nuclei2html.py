#!/usr/bin/env python3
# ==========================================================================
# nuclei2html.py  -  Web vulnerability report.
#
# Recursively parses nuclei text output under a run directory, groups findings
# by host, dedupes templates, and renders a severity-sorted HTML report.
#
#   python3 nuclei2html.py -i reconoutput/<project>/<mode> -o web_report.html
# ==========================================================================

import argparse
import os
import re
from collections import defaultdict
from datetime import datetime

NUCLEI_RE = re.compile(r"\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]\s+(http[s]?://[^\s]+)")
HOST_RE = re.compile(r"http[s]?://([^:/]+)")
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}


class Finding:
    def __init__(self, template, severity, url):
        self.template = template
        self.severity = severity.upper()
        self.url = url


class Host:
    def __init__(self, ip):
        self.ip = ip
        self.findings = []


def parse_nuclei_file(file):
    hosts = {}
    with open(file, encoding="utf8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = NUCLEI_RE.match(line)
            if not m:
                continue
            template, severity, url = m.group(1), m.group(3), m.group(4)
            hm = HOST_RE.search(url)
            if not hm:
                continue
            ip = hm.group(1)
            hosts.setdefault(ip, Host(ip)).findings.append(Finding(template, severity, url))
    return hosts


def load_all_results(root):
    all_hosts = {}
    for root_dir, _dirs, files in os.walk(root):
        for file in files:
            if not file.endswith(".txt"):
                continue
            for ip, host in parse_nuclei_file(os.path.join(root_dir, file)).items():
                if ip not in all_hosts:
                    all_hosts[ip] = host
                else:
                    all_hosts[ip].findings.extend(host.findings)
    return list(all_hosts.values())


STYLE = """
body{background:#0f172a;color:#e5e7eb;font-family:Segoe UI,Arial;margin:0;}
.header{background:#020617;padding:25px;border-bottom:2px solid #1e293b;}
h1{margin:0;color:#38bdf8;}
.container{padding:25px;}
.summary{background:#020617;padding:18px 20px;border-radius:10px;margin-bottom:25px;}
.summary span{margin-right:22px;font-size:15px;}
.host{background:#020617;margin-bottom:30px;padding:20px;border-radius:10px;box-shadow:0 0 20px rgba(0,0,0,0.6);}
table{width:100%;border-collapse:collapse;margin-top:15px;}
th{background:#020617;color:#38bdf8;text-align:left;padding:10px;border-bottom:1px solid #334155;}
td{padding:10px;border-bottom:1px solid #1e293b;vertical-align:top;}
ul{margin:0;padding-left:18px;}
.CRITICAL{color:#ef4444;font-weight:bold;}
.HIGH{color:#f97316;font-weight:bold;}
.MEDIUM{color:#eab308;font-weight:bold;}
.LOW{color:#22c55e;font-weight:bold;}
.INFO{color:#94a3b8;}
.UNKNOWN{color:#94a3b8;}
"""


class Report:

    def generate(self, hosts):
        totals = defaultdict(int)
        for h in hosts:
            for f in h.findings:
                totals[f.severity] += 1
        # rank hosts by worst finding present
        hosts = sorted(
            hosts,
            key=lambda h: min((_SEV_ORDER.get(f.severity, 5) for f in h.findings), default=5),
        )

        html = [f"<html><head><title>Web Vulnerability Report</title><style>{STYLE}</style></head><body>"]
        html.append('<div class="header"><h1>Web Vulnerability Report (nuclei)</h1>')
        html.append(f"<div>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div></div>")
        html.append('<div class="container">')

        html.append('<div class="summary">')
        html.append(f"<span>Hosts: <b>{len(hosts)}</b></span>")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if totals.get(sev):
                html.append(f"<span class='{sev}'>{sev}: {totals[sev]}</span>")
        html.append("</div>")

        for h in hosts:
            html.append(
                f"<div class='host'><h2>Host: {h.ip}</h2>"
                "<table><tr><th style='width:260px'>Template / CVE</th>"
                "<th style='width:120px'>Severity</th><th>URLs</th></tr>"
            )
            uniq = defaultdict(list)
            for f in h.findings:
                uniq[(f.template, f.severity)].append(f.url)

            for (template, severity), urls in sorted(
                uniq.items(), key=lambda kv: _SEV_ORDER.get(kv[0][1], 5)
            ):
                shown = "".join(f"<li>{u}</li>" for u in urls[:12])
                if len(urls) > 12:
                    shown += f"<li>... {len(urls) - 12} more</li>"
                html.append(
                    f"<tr><td>{template}</td><td class='{severity}'>{severity}</td>"
                    f"<td><ul>{shown}</ul></td></tr>"
                )
            html.append("</table></div>")

        html.append("</div></body></html>")
        return "\n".join(html)


def main():
    ap = argparse.ArgumentParser(description="Render a web-vuln HTML report from nuclei output.")
    ap.add_argument("-i", required=True, help="root directory containing nuclei txt outputs")
    ap.add_argument("-o", required=True, help="output HTML file")
    args = ap.parse_args()

    hosts = load_all_results(args.i)
    with open(args.o, "w", encoding="utf8") as f:
        f.write(Report().generate(hosts))
    print(f"[nuclei2html] {len(hosts)} hosts -> {args.o}")


if __name__ == "__main__":
    main()
