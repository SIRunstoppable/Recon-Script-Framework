#!/usr/bin/env python3
"""
check_misconfig.py

Goes beyond simple "header present/missing" (that's check_cors_headers.py's
job) into whether what's actually configured is safe, plus several other
common misconfiguration classes:

  1. CSP quality       — flags 'unsafe-inline', 'unsafe-eval', wildcard '*'
                          sources, or a completely permissive policy.
  2. HSTS quality       — flags missing/short max-age (<6 months) or a
                          missing includeSubDomains directive.
  3. X-Frame-Options    — flags missing header or a non-restrictive value.
  4. Insecure cookies   — for every Set-Cookie header, flags missing
                          Secure / HttpOnly / SameSite attributes.
  5. Directory listing  — probes a handful of common directories for
                          Apache/Nginx-style "Index of /" listing pages.
  6. Debug headers      — flags verbose Server/X-Powered-By version strings
                          and framework-specific debug headers (Symfony's
                          X-Debug-Token, ASP.NET version headers, etc.), plus
                          a light body scan for common debug/stack-trace
                          signatures (Whoops, Werkzeug, Django debug page...).
  7. Exposed health/metrics endpoints — probes common health-check and
                          metrics paths; flags ones that return 200 with a
                          baseline-filtered response (soft-404 aware), since
                          these often leak internal service/version/DB info.

Reads:  live/httpx_live.txt
Writes: report/misconfig.json
        report/misconfig.txt

Usage: run from WORKDIR root
    python3 check_misconfig.py

Requires: requests (pip install requests --break-system-packages)
"""
import os
import re
import json
import random
import string
import concurrent.futures

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("  ⚠ 'requests' not installed — skipping misconfig check.")
    print("    pip install requests --break-system-packages")
    raise SystemExit(0)

TIMEOUT = 8
MAX_WORKERS = 15

DIRECTORY_LISTING_PATHS = ["/", "/images/", "/uploads/", "/assets/", "/backup/", "/files/", "/static/", "/media/"]

HEALTH_PATHS = [
    "/health", "/healthz", "/_health", "/status", "/ping",
    "/actuator/health", "/actuator/metrics", "/actuator/info",
    "/metrics", "/debug/vars", "/server-status", "/server-info",
    "/api/health", "/api/status",
]

DEBUG_HEADER_KEYS = ["X-Debug-Token", "X-Debug-Token-Link", "X-AspNet-Version", "X-AspNetMvc-Version"]

DEBUG_BODY_SIGNATURES = [
    "whoops", "werkzeug", "django debug", "traceback (most recent call last)",
    "fatal error:", "warning: include", "stack trace:", "laravel debugbar",
    "symfony exception",
]

DIR_LISTING_SIGNATURES = ["index of /", "parent directory</a>", "<title>index of"]


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


def check_headers(host, r):
    findings = []
    headers = r.headers

    csp = headers.get("Content-Security-Policy")
    if not csp:
        findings.append({"category": "CSP", "severity": "medium", "detail": "no Content-Security-Policy header set"})
    else:
        lc = csp.lower()
        if "unsafe-inline" in lc or "unsafe-eval" in lc:
            findings.append({"category": "CSP", "severity": "medium", "detail": f"weak CSP allows unsafe-inline/unsafe-eval: {csp[:200]}"})
        elif re.search(r"(default-src|script-src)\s+\*", lc):
            findings.append({"category": "CSP", "severity": "medium", "detail": f"CSP allows wildcard script sources: {csp[:200]}"})

    hsts = headers.get("Strict-Transport-Security")
    if not hsts:
        findings.append({"category": "HSTS", "severity": "low", "detail": "no Strict-Transport-Security header (only relevant over HTTPS)"})
    else:
        m = re.search(r"max-age=(\d+)", hsts)
        max_age = int(m.group(1)) if m else 0
        if max_age < 15552000:  # ~6 months
            findings.append({"category": "HSTS", "severity": "low", "detail": f"HSTS max-age too short ({max_age}s): {hsts}"})
        if "includesubdomains" not in hsts.lower():
            findings.append({"category": "HSTS", "severity": "low", "detail": f"HSTS missing includeSubDomains: {hsts}"})

    xfo = headers.get("X-Frame-Options")
    if not xfo:
        findings.append({"category": "X-Frame-Options", "severity": "medium", "detail": "missing — page may be embeddable in a clickjacking iframe"})
    elif xfo.upper() not in ("DENY", "SAMEORIGIN"):
        findings.append({"category": "X-Frame-Options", "severity": "medium", "detail": f"non-restrictive value: {xfo}"})

    return findings


def check_cookies(r):
    findings = []
    try:
        raw_cookies = r.raw.headers.getlist("Set-Cookie")
    except Exception:
        single = r.headers.get("Set-Cookie")
        raw_cookies = [single] if single else []

    for cookie_str in raw_cookies:
        if not cookie_str:
            continue
        lc = cookie_str.lower()
        name = cookie_str.split("=")[0].strip()
        missing = []
        if "secure" not in lc:
            missing.append("Secure")
        if "httponly" not in lc:
            missing.append("HttpOnly")
        if "samesite" not in lc:
            missing.append("SameSite")
        if missing:
            findings.append({
                "category": "Insecure Cookie", "severity": "low", "cookie": name,
                "detail": f"missing attribute(s): {', '.join(missing)}",
            })
    return findings


def check_debug(r):
    findings = []
    server = r.headers.get("Server", "")
    if re.search(r"\d+\.\d+", server):  # version number present = overly verbose
        findings.append({"category": "Debug/Info Disclosure", "severity": "low", "detail": f"verbose Server header: {server}"})

    powered_by = r.headers.get("X-Powered-By")
    if powered_by:
        findings.append({"category": "Debug/Info Disclosure", "severity": "low", "detail": f"X-Powered-By discloses stack info: {powered_by}"})

    for key in DEBUG_HEADER_KEYS:
        if key in r.headers:
            findings.append({"category": "Debug/Info Disclosure", "severity": "medium", "detail": f"{key} header present — debug mode likely enabled"})

    body_sample = (r.text or "")[:20000].lower()
    for sig in DEBUG_BODY_SIGNATURES:
        if sig in body_sample:
            findings.append({"category": "Debug/Info Disclosure", "severity": "high", "detail": f"response body contains debug/stack-trace signature: '{sig}'"})
            break  # one hit is enough to flag the page

    return findings


def check_directory_listing(host):
    findings = []
    for path in DIRECTORY_LISTING_PATHS:
        try:
            r = requests.get(host + path, timeout=TIMEOUT, verify=False, allow_redirects=False)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        body = (r.text or "")[:5000].lower()
        if any(sig in body for sig in DIR_LISTING_SIGNATURES):
            findings.append({"category": "Directory Listing", "severity": "medium", "url": host + path, "detail": "directory listing page detected"})
    return findings


def check_health_endpoints(host):
    findings = []
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    try:
        base = requests.get(f"{host}/__nonexistent_{rand}__", timeout=TIMEOUT, verify=False, allow_redirects=False)
        base_status, base_len = base.status_code, len(base.content)
    except Exception:
        base_status, base_len = None, None

    for path in HEALTH_PATHS:
        try:
            r = requests.get(host + path, timeout=TIMEOUT, verify=False, allow_redirects=False)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        if base_status is not None and r.status_code == base_status and abs(len(r.content) - (base_len or 0)) < 15:
            continue  # soft-404
        snippet = (r.text or "")[:300]
        findings.append({"category": "Exposed Health Endpoint", "severity": "low", "url": host + path, "response_preview": snippet})
    return findings


def scan_host(host):
    findings = []
    try:
        r = requests.get(host, timeout=TIMEOUT, verify=False, allow_redirects=True)
        findings.extend(check_headers(host, r))
        findings.extend(check_cookies(r))
        findings.extend(check_debug(r))
    except Exception:
        pass
    findings.extend(check_directory_listing(host))
    findings.extend(check_health_endpoints(host))
    for f in findings:
        f["host"] = host
    return findings


def main():
    hosts = read_hosts()
    all_findings = []

    if hosts:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            for i, result in enumerate(ex.map(scan_host, hosts), 1):
                all_findings.extend(result)
                print(f"\r  checking misconfigurations  {i}/{len(hosts)}   ", end="", flush=True)
    print("")

    os.makedirs("report", exist_ok=True)
    by_category = {}
    for f in all_findings:
        by_category.setdefault(f["category"], []).append(f)

    summary = {
        "hosts_scanned": len(hosts),
        "total_findings": len(all_findings),
        "by_category_count": {k: len(v) for k, v in by_category.items()},
        "findings": all_findings,
    }
    with open("report/misconfig.json", "w") as f:
        json.dump(summary, f, indent=2)

    with open("report/misconfig.txt", "w") as f:
        f.write(f"Hosts scanned: {len(hosts)}\n")
        f.write(f"Total misconfiguration findings: {len(all_findings)}\n\n")
        for cat, items in sorted(by_category.items()):
            f.write(f"=== {cat} ({len(items)}) ===\n")
            for it in items:
                extra = it.get("url") or it.get("cookie") or ""
                f.write(f"[{it['severity'].upper()}] {it['host']} {extra}\n    {it.get('detail') or it.get('response_preview','')}\n")
            f.write("\n")

    print(f"  ✓ Misconfig check: {len(all_findings)} finding(s) across {len(by_category)} categories -> report/misconfig.*")


if __name__ == "__main__":
    main()
