#!/usr/bin/env python3
"""
check_cors_headers.py

For every live host, sends a handful of requests with crafted Origin headers
to detect common CORS misconfigurations, then checks for missing baseline
security headers on a normal request.

CORS tests (each is one extra GET request with a custom Origin header —
lightweight, read-only, standard technique any browser-based attacker could
trigger just by visiting a page):
  1. Arbitrary origin reflection: Origin: https://evil-cors-test-<rand>.com
     -> if the response's Access-Control-Allow-Origin echoes this back,
        any website can read this API's responses in a victim's browser.
  2. Null origin: Origin: null
     -> some servers whitelist "null" thinking it's safe; it's trivially
        forgeable from a sandboxed iframe or a local file.
  3. Prefix/suffix substring tricks: Origin: https://evil<target-domain>
     and https://<target-domain>.evil.com
     -> catches broken regex allowlists (e.g. matching "contains" instead
        of "equals" the trusted domain).

Severity is escalated to critical/high specifically when
Access-Control-Allow-Credentials: true is present alongside a reflected/
permissive origin, since that's what allows an attacker to read
authenticated (cookie-bearing) responses.

Security headers checked: Content-Security-Policy, X-Frame-Options,
Strict-Transport-Security, X-Content-Type-Options.

Reads:  live/httpx_live.txt
Writes: report/cors_headers.json
        report/cors_headers.txt

Usage: run from WORKDIR root
    python3 check_cors_headers.py

Requires: requests (pip install requests --break-system-packages)
"""
import os
import json
import random
import string
import concurrent.futures
from urllib.parse import urlparse

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("  ⚠ 'requests' not installed — skipping CORS/header check.")
    print("    pip install requests --break-system-packages")
    raise SystemExit(0)

TIMEOUT = 8
MAX_WORKERS = 15

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
]


def read_hosts(path="live/httpx_live.txt"):
    hosts = []
    if not os.path.isfile(path):
        return hosts
    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            url = line.split()[0]
            if url.startswith("http"):
                hosts.append(url.rstrip("/"))
    return sorted(set(hosts))


def build_origin_tests(host):
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    tests = [
        (f"https://evil-cors-test-{rand}.com", "arbitrary_origin_reflected"),
        ("null", "null_origin_accepted"),
    ]
    hostname = urlparse(host).hostname or ""
    if hostname:
        tests.append((f"https://evil{hostname}", "prefix_substring_bypass"))
        tests.append((f"https://{hostname}.evil-{rand}.com", "suffix_substring_bypass"))
    return tests


def test_cors(host):
    findings = []
    for origin, test_name in build_origin_tests(host):
        try:
            r = requests.get(host, headers={"Origin": origin}, timeout=TIMEOUT, verify=False, allow_redirects=False)
        except Exception:
            continue
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = (r.headers.get("Access-Control-Allow-Credentials") or "").lower() == "true"
        if not acao:
            continue

        if acao == origin and origin != "null":
            findings.append({
                "host": host, "test": test_name, "origin_sent": origin,
                "acao_returned": acao, "credentials_allowed": acac,
                "severity": "critical" if acac else "high",
                "note": "server reflects an arbitrary/attacker-controlled Origin back in ACAO"
                        + (" WITH credentials allowed — attacker can read authenticated responses" if acac else ""),
            })
        elif acao == "*" and acac:
            findings.append({
                "host": host, "test": "wildcard_with_credentials", "origin_sent": origin,
                "acao_returned": acao, "credentials_allowed": True, "severity": "medium",
                "note": "ACAO:* combined with ACAC:true is spec-invalid but indicates a misconfigured CORS policy",
            })
        elif acao == "null" and test_name == "null_origin_accepted":
            findings.append({
                "host": host, "test": test_name, "origin_sent": origin,
                "acao_returned": acao, "credentials_allowed": acac,
                "severity": "high" if acac else "medium",
                "note": "server explicitly allows the 'null' origin (forgeable via sandboxed iframe/local file)",
            })
    return findings


def check_security_headers(host):
    try:
        r = requests.get(host, timeout=TIMEOUT, verify=False, allow_redirects=True)
    except Exception:
        return None
    missing = [h for h in SECURITY_HEADERS if h not in r.headers]
    return {"host": host, "missing_headers": missing}


def scan_host(host):
    return test_cors(host), check_security_headers(host)


def main():
    hosts = read_hosts()
    cors_findings = []
    header_findings = []

    if hosts:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            for i, (cors, headers) in enumerate(ex.map(scan_host, hosts), 1):
                cors_findings.extend(cors)
                if headers and headers["missing_headers"]:
                    header_findings.append(headers)
                print(f"\r  checking CORS + security headers  {i}/{len(hosts)}   ", end="", flush=True)
    print("")

    os.makedirs("report", exist_ok=True)
    summary = {
        "hosts_scanned": len(hosts),
        "cors_findings": cors_findings,
        "hosts_missing_headers": header_findings,
    }
    with open("report/cors_headers.json", "w") as f:
        json.dump(summary, f, indent=2)

    with open("report/cors_headers.txt", "w") as f:
        f.write(f"Hosts scanned: {len(hosts)}\n")
        f.write(f"CORS misconfigurations found: {len(cors_findings)}\n")
        f.write(f"Hosts missing 1+ security header: {len(header_findings)}\n\n")

        if cors_findings:
            f.write("=== CORS MISCONFIGURATIONS ===\n")
            for c in sorted(cors_findings, key=lambda x: x["severity"] != "critical"):
                f.write(f"[{c['severity'].upper()}] {c['host']}  (test: {c['test']})\n")
                f.write(f"    Origin sent: {c['origin_sent']}  ->  ACAO: {c['acao_returned']}  Credentials: {c['credentials_allowed']}\n")
                f.write(f"    {c['note']}\n")
            f.write("\n")

        if header_findings:
            f.write("=== MISSING SECURITY HEADERS ===\n")
            for h in header_findings:
                f.write(f"{h['host']}: missing {', '.join(h['missing_headers'])}\n")

    print(f"  ✓ CORS/header check: {len(cors_findings)} CORS issues, "
          f"{len(header_findings)} hosts with missing headers -> report/cors_headers.*")


if __name__ == "__main__":
    main()
