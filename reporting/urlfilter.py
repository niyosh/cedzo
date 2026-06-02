#!/usr/bin/env python3
# ==========================================================================
# urlfilter.py  -  Merge + prioritise crawled/brute-forced URLs.
#
# Consumes katana and/or dirsearch output, keeps the interesting endpoints
# (good status codes, parameters, admin/login paths, dynamic extensions),
# drops static assets and deep-crawl noise, dedupes, and writes a clean
# target list suitable for feeding to nuclei.
#
#   python3 urlfilter.py katana.txt dirsearch.txt -o filtered_urls.txt
# ==========================================================================

import argparse
import hashlib
import os

STATIC_EXT = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".webp", ".mp4", ".pdf", ".zip",
)
GOOD_CODES = {"200", "302", "401", "403"}
KEYWORDS = (
    "admin", "login", "console", "dashboard", "manager",
    "phpmyadmin", "api", "test", "dev", "config", "secure",
)
DYNAMIC_EXT = (".php", ".jsp", ".asp", ".aspx", ".do", ".action", ".json")


def filter_urls(files, outfile):
    seen = set()
    kept = 0

    with open(outfile, "w", encoding="utf8") as out:
        for path in files:
            if not path or not os.path.exists(path):
                continue

            with open(path, encoding="utf8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue

                    # -------- dirsearch format: "200    1234B   http://..." --------
                    if line[0].isdigit():
                        parts = line.split()
                        if len(parts) < 3:
                            continue
                        if parts[0] not in GOOD_CODES:
                            continue
                        url = parts[-1]

                    # -------- katana format: a bare URL per line --------
                    else:
                        url = line
                        low = url.lower()
                        # keep only parameterised / interesting / dynamic endpoints
                        if (
                            "?" not in url
                            and not any(k in low for k in KEYWORDS)
                            and not low.endswith(DYNAMIC_EXT)
                        ):
                            continue
                        # drop deep-crawl noise
                        if url.count("/") > 6:
                            continue

                    if url.lower().endswith(STATIC_EXT):
                        continue

                    h = hashlib.sha1(url.encode()).hexdigest()
                    if h in seen:
                        continue
                    seen.add(h)
                    out.write(url + "\n")
                    kept += 1

    return kept


def main():
    ap = argparse.ArgumentParser(description="Merge and prioritise crawled URLs for scanning.")
    ap.add_argument("files", nargs="+", help="katana / dirsearch output files")
    ap.add_argument("-o", "--out", required=True, help="filtered URL list output")
    args = ap.parse_args()

    kept = filter_urls(args.files, args.out)
    print(f"[urlfilter] kept {kept} prioritised URLs -> {args.out}")


if __name__ == "__main__":
    main()
