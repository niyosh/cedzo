#!/usr/bin/env python3
# ==========================================================================
# nmap2html.py  -  Infrastructure intelligence report.
#
# Recursively parses every *.nmap file under a run directory, runs a service
# intelligence pass (legacy protocols, weak crypto, exposed DBs, NSE-derived
# findings), scores per-host risk, and renders a single HTML report.
#
#   python3 nmap2html.py -i loot/run-<ts> -o nmap_report.html
# ==========================================================================

import argparse
import math
import os
import re
from datetime import datetime
from enum import Enum
from typing import Dict, List


# ================= MODELS =================

class Severity(Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Finding:
    def __init__(self, title, severity):
        self.title = title
        self.severity = severity


class Service:
    def __init__(self, port, proto, name, version=""):
        self.port = port
        self.proto = proto
        self.name = name.lower()
        self.version = version.lower()
        self.scripts: Dict[str, str] = {}
        self.findings: List[Finding] = []


class Host:
    def __init__(self, ip):
        self.ip = ip
        self.services: List[Service] = []
        self.risk = 0.0


# ================= PARSER =================

class Parser:

    def parse(self, file):
        hosts = []
        ch = None
        cs = None

        with open(file, encoding="utf8", errors="ignore") as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()

            m = re.match(r"Nmap scan report for (.+)", line)
            if m:
                if ch:
                    hosts.append(ch)
                ch = Host(m.group(1))
                cs = None
                continue

            m = re.match(r"(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
            if m and ch:
                cs = Service(int(m.group(1)), m.group(2), m.group(3), m.group(4))
                ch.services.append(cs)
                continue

            if cs and (line.startswith("|") or line.startswith("|_")):
                line = line.lstrip("|_").strip()
                if ":" in line:
                    k, v = line.split(":", 1)
                    cs.scripts[k.strip().lower()] = v.strip().lower()

        if ch:
            hosts.append(ch)

        return hosts


# ================= INTELLIGENCE =================

class Intelligence:

    def analyze(self, s: Service):
        banner = f"{s.name} {s.version}"
        sc = s.scripts

        rce = ["vsftpd 2.3.4", "unrealircd", "distccd", "bindshell", "java-rmi", "drb", "ajp", "tomcat"]
        for sig in rce:
            if sig in banner:
                s.findings.append(Finding("Possible Remote Code Execution Service", Severity.CRITICAL))

        legacy = {
            "telnet": "Cleartext Remote Login", "rlogin": "Legacy Remote Login",
            "rexec": "Remote Command Service", "vnc": "Remote Desktop Exposure",
            "x11": "X11 Exposure",
        }
        if s.name in legacy:
            s.findings.append(Finding(legacy[s.name], Severity.HIGH))

        if s.name in ["mysql", "postgresql", "mssql", "oracle", "ms-sql", "mongodb", "redis"]:
            s.findings.append(Finding("Database Service Exposed", Severity.HIGH))

        if s.name in ["rpcbind", "nfs", "mountd", "status", "nlockmgr"]:
            s.findings.append(Finding("RPC/NFS Exposure", Severity.MEDIUM))

        if "apache" in banner and "2.2" in banner:
            s.findings.append(Finding("Outdated Apache", Severity.HIGH))
        if "openssh" in banner and ("4." in banner or "5." in banner):
            s.findings.append(Finding("Outdated OpenSSH", Severity.HIGH))
        if "samba" in banner:
            s.findings.append(Finding("Outdated Samba", Severity.HIGH))
        if "bind" in banner:
            s.findings.append(Finding("DNS Version Disclosure", Severity.MEDIUM))

        # NSE-derived
        if "ftp-anon" in sc:
            s.findings.append(Finding("Anonymous FTP Enabled", Severity.HIGH))
        if "http-title" in sc and ("test" in sc["http-title"] or "metasploitable" in sc["http-title"]):
            s.findings.append(Finding("Default/Test Web App", Severity.MEDIUM))
        if "http-server-header" in sc and "apache/2.2" in sc["http-server-header"]:
            s.findings.append(Finding("Outdated Web Server Header", Severity.HIGH))
        if "mysql-info" in sc:
            s.findings.append(Finding("Database Info Disclosure", Severity.MEDIUM))
        if "rpcinfo" in sc:
            s.findings.append(Finding("Multiple RPC Services", Severity.MEDIUM))
        if "smb-security-mode" in sc and "disabled" in sc["smb-security-mode"]:
            s.findings.append(Finding("SMB Signing Disabled", Severity.HIGH))
        if "vnc-info" in sc:
            s.findings.append(Finding("Weak VNC Authentication", Severity.HIGH))
        if "ssl-cert" in sc:
            s.findings.append(Finding("Expired/Self-Signed Certificate", Severity.MEDIUM))
        if "sslv2" in sc:
            s.findings.append(Finding("SSLv2 Supported", Severity.CRITICAL))
        if any(w in str(sc) for w in ["rc4", "des", "export", "null"]):
            s.findings.append(Finding("Weak TLS Cipher", Severity.HIGH))
        if "ssh-hostkey" in sc and "1024" in sc["ssh-hostkey"]:
            s.findings.append(Finding("Weak SSH Key", Severity.MEDIUM))


# ================= RISK =================

class Risk:
    weights = {
        Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 3,
        Severity.HIGH: 7, Severity.CRITICAL: 10,
    }

    def score(self, h: Host):
        t = sum(self.weights[f.severity] for s in h.services for f in s.findings)
        if h.services:
            h.risk = t / math.log(len(h.services) + 1)


# ================= REPORT =================

STYLE = """
body{background:#0f172a;color:#e5e7eb;font-family:Segoe UI,Arial;margin:0;}
.header{background:#020617;padding:25px;border-bottom:2px solid #1e293b;}
h1{margin:0;color:#38bdf8;}
.container{padding:25px;}
.summary{background:#020617;padding:18px 20px;border-radius:10px;margin-bottom:25px;}
.summary span{margin-right:22px;font-size:15px;}
.host{background:#020617;margin-bottom:30px;padding:20px;border-radius:10px;box-shadow:0 0 20px rgba(0,0,0,0.6);}
.risk{font-size:18px;font-weight:bold;color:#f87171;}
table{width:100%;border-collapse:collapse;margin-top:15px;}
th{background:#020617;color:#38bdf8;text-align:left;padding:10px;border-bottom:1px solid #334155;}
td{padding:10px;border-bottom:1px solid #1e293b;vertical-align:top;}
ul{margin:0;padding-left:18px;}
.CRITICAL{color:#ef4444;font-weight:bold;}
.HIGH{color:#f97316;font-weight:bold;}
.MEDIUM{color:#eab308;font-weight:bold;}
.LOW{color:#22c55e;font-weight:bold;}
.INFO{color:#94a3b8;}
.port{font-weight:bold;color:#cbd5f5;}
.service{color:#a5f3fc;}
.version{color:#cbd5f5;font-size:13px;}
"""

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class Report:

    def generate(self, hosts):
        hosts = sorted(hosts, key=lambda h: h.risk, reverse=True)

        totals = {sev.name: 0 for sev in Severity}
        for h in hosts:
            for s in h.services:
                for f in s.findings:
                    totals[f.severity.name] += 1

        html = [f"<html><head><title>Infrastructure Report</title><style>{STYLE}</style></head><body>"]
        html.append('<div class="header"><h1>Infrastructure Intelligence Report</h1>')
        html.append(f"<div>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div></div>")
        html.append('<div class="container">')

        html.append('<div class="summary">')
        html.append(f"<span>Hosts: <b>{len(hosts)}</b></span>")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            html.append(f"<span class='{sev}'>{sev}: {totals[sev]}</span>")
        html.append("</div>")

        for h in hosts:
            html.append(
                f"<div class='host'><h2>Host: {h.ip}</h2>"
                f"<div class='risk'>Risk Score: {round(h.risk, 2)}</div>"
                "<table><tr><th style='width:80px'>Port</th><th style='width:160px'>Service</th>"
                "<th style='width:260px'>Version</th><th>Findings</th></tr>"
            )
            for s in sorted(h.services, key=lambda x: x.port):
                ordered = sorted(s.findings, key=lambda f: _SEV_ORDER[f.severity.name])
                findings = "<ul>" + "".join(
                    f"<li class='{f.severity.name}'>{f.severity.name}: {f.title}</li>" for f in ordered
                ) + "</ul>"
                html.append(
                    f"<tr><td class='port'>{s.port}/{s.proto}</td><td class='service'>{s.name}</td>"
                    f"<td class='version'>{s.version or '-'}</td><td>{findings}</td></tr>"
                )
            html.append("</table></div>")

        html.append("</div></body></html>")
        return "\n".join(html)


# ================= MAIN =================

def main():
    ap = argparse.ArgumentParser(description="Render an infrastructure HTML report from nmap output.")
    ap.add_argument("-i", required=True, help="root results/run directory")
    ap.add_argument("-o", required=True, help="output HTML file")
    args = ap.parse_args()

    parser = Parser()
    hosts_map: Dict[str, Host] = {}

    for root, _dirs, files in os.walk(args.i):
        for file in files:
            if file.endswith(".nmap"):
                for ph in parser.parse(os.path.join(root, file)):
                    hosts_map.setdefault(ph.ip, Host(ph.ip)).services.extend(ph.services)

    # ced emits several .nmap files per host (full_tcp without versions,
    # service with them). Collapse duplicate ports, keeping the richest entry.
    def _richness(s: Service):
        return (bool(s.version), len(s.scripts), len(s.name))

    hosts = []
    for h in hosts_map.values():
        best: Dict[tuple, Service] = {}
        for s in h.services:
            key = (s.port, s.proto)
            if key not in best or _richness(s) > _richness(best[key]):
                best[key] = s
        h.services = list(best.values())
        hosts.append(h)

    intel, risk = Intelligence(), Risk()
    for h in hosts:
        for s in h.services:
            intel.analyze(s)
        risk.score(h)

    with open(args.o, "w", encoding="utf8") as f:
        f.write(Report().generate(hosts))

    print(f"[nmap2html] {len(hosts)} hosts -> {args.o}")


if __name__ == "__main__":
    main()
