#!/usr/bin/env python3
# ==========================================================================
# urlfilter.py  -  Consolidate + de-noise crawled/brute-forced URLs.
#
# Consumes katana (bare URLs) and feroxbuster/dirsearch (status-prefixed)
# output, keeps the interesting endpoints, drops junk, and collapses
# near-duplicates so nuclei gets a tight target list instead of thousands of
# redundant URLs.
#
# De-noising performed:
#   * drop non-absolute URLs (e.g. a bare "login.php")
#   * drop static assets (by path extension, ignoring the query string)
#   * drop Apache mod_autoindex column-sort links   (?C=...&O=...)
#   * drop documentation/templated placeholder URLs (?get=BEANNAME&att=MYKEY)
#   * status-filter feroxbuster/dirsearch lines to interesting codes
#   * for katana bare URLs, keep only parameterised / dynamic / keyworded paths
#     and drop deep-crawl noise
#   * collapse duplicates by (scheme, host, path, sorted param NAMES) so that
#     index.php?page=a, index.php?page=b, ... become a single representative
#
#   python3 urlfilter.py katana.txt ferox_*.txt -o filtered_urls.txt
# ==========================================================================

import argparse
import os
import re
from urllib.parse import urlsplit, parse_qsl

STATIC_EXT = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".webp", ".mp4", ".pdf", ".zip", ".map",
)
# Interesting HTTP status codes from feroxbuster/dirsearch output.
GOOD_CODES = {"200", "204", "301", "302", "307", "308", "401", "403", "405"}
KEYWORDS = (
    "admin", "login", "console", "dashboard", "manager",
    "phpmyadmin", "api", "test", "dev", "config", "secure",
)
DYNAMIC_EXT = (".php", ".jsp", ".asp", ".aspx", ".do", ".action", ".json")

# Runs of >=4 uppercase letters in the query usually mean a templated example
# URL copied from docs (BEANNAME, MYATTRIBUTE, METHODNAME, NEWVALUE, ...).
PLACEHOLDER_RE = re.compile(r"[A-Z]{4,}")
MAX_DEPTH = 6  # max path segments for katana bare URLs


def extract(line):
    """Return (url, source) where source is 'status' or 'bare', or (None, None)."""
    line = line.strip()
    if not line:
        return None, None
    if line[0].isdigit():
        # status-prefixed (feroxbuster / dirsearch)
        parts = line.split()
        if len(parts) < 2 or parts[0] not in GOOD_CODES:
            return None, None
        for tok in reversed(parts):
            if tok.startswith(("http://", "https://")):
                return tok, "status"
        return None, None
    if line.startswith(("http://", "https://")):
        return line, "bare"
    return None, None  # bare relative path -> not a usable target


def is_junk(parts):
    keys = {k for k, _ in parse_qsl(parts.query, keep_blank_values=True)}
    # Apache directory-listing sort links: ?C=N;O=D etc.
    if keys and keys <= {"C", "O"}:
        return True
    # templated/example placeholder URLs
    if PLACEHOLDER_RE.search(parts.query):
        return True
    # static asset (check the path, not the whole URL with its query string)
    if parts.path.lower().endswith(STATIC_EXT):
        return True
    return False


def interesting_bare(url):
    low = url.lower()
    if "?" not in url and not any(k in low for k in KEYWORDS) and not low.endswith(DYNAMIC_EXT):
        return False
    if url.count("/") > MAX_DEPTH:
        return False
    return True


def canonical_key(parts):
    keys = tuple(sorted(k for k, _ in parse_qsl(parts.query, keep_blank_values=True)))
    return (parts.scheme, parts.netloc, parts.path, keys)


def filter_urls(files, outfile):
    seen = set()
    kept = dropped = 0

    with open(outfile, "w", encoding="utf8") as out:
        for path in files:
            if not path or not os.path.exists(path):
                continue
            with open(path, encoding="utf8", errors="ignore") as fh:
                for line in fh:
                    url, source = extract(line)
                    if url is None:
                        continue
                    url = url.split("#", 1)[0]  # drop fragment
                    parts = urlsplit(url)

                    if is_junk(parts):
                        dropped += 1
                        continue
                    if source == "bare" and not interesting_bare(url):
                        dropped += 1
                        continue

                    key = canonical_key(parts)
                    if key in seen:
                        dropped += 1
                        continue
                    seen.add(key)
                    out.write(url + "\n")
                    kept += 1

    return kept, dropped


def main():
    ap = argparse.ArgumentParser(description="Consolidate and de-noise crawled URLs for scanning.")
    ap.add_argument("files", nargs="+", help="katana / feroxbuster / dirsearch output files")
    ap.add_argument("-o", "--out", required=True, help="filtered URL list output")
    args = ap.parse_args()

    kept, dropped = filter_urls(args.files, args.out)
    print(f"[urlfilter] kept {kept} prioritised URLs, dropped {dropped} junk/dup -> {args.out}")


if __name__ == "__main__":
    main()
