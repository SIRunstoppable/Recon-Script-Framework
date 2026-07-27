#!/usr/bin/env python3
"""
check_ip_bypass.py

Tests a well-known access-control vulnerability class (CWE-290: Authentication
Bypass by Spoofing): some applications trust IP-restriction headers set by an
upstream proxy/load balancer (X-Forwarded-For, X-Real-IP, etc.) without
verifying the request actually came through that proxy. If the app itself
is directly reachable, an attacker can just set those headers on a direct
request and potentially impersonate an "internal" or "trusted" IP.

This is a check of the TARGET's own access-control implementation — it does
NOT help the scanner evade the target's defenses (see rate_limiter.py /
RECON_RATE_LIMIT for good-citizen throttling; this script does not touch that).

Method, per candidate restricted path:
  1. Request it plainly (no spoofed headers). If the result is NOT 401/403,
     there's nothing to bypass — skip it (this also naturally avoids wasting
     requests on paths that were never actually restricted).
  2. Re-request the same path with each spoofed-header/value combination one
     at a time. If any combination flips the response away from 401/403
     (typically to 200), that's a confirmed IP-restriction bypass.

Candidate paths come from:
  - report/sensitive_files.json findings already marked "protected" (401/403)
  - report/content_discovery.json findings with status 401/403
  - a small fallback list of common admin-ish paths, checked directly, in
    case neither of the above ran or found anything

Reads:  live/httpx_live.txt, report/sensitive_files.json, report/content_discovery.json
Writes: report/ip_bypass.json
        report/ip_bypass.txt

Usage: run from WORKDIR root
    python3 check_ip_bypass.py

Requires: requests (pip install requests --break-system-packages)
"""
import os
import json
import concurrent.futures
from urllib.parse import urlparse

try:
    from rate_limiter import get, MAX_WORKERS
except ImportError:
    print("  ⚠ rate_limiter.py not found next to this script — skipping IP bypass check.")
    raise SystemExit(0)

TIMEOUT = 8

# Headers apps sometimes trust for "where did this request originate" without
# verifying it actually came from a trusted upstream proxy.
SPOOF_HEADERS = [
    "X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Client-IP",
    "X-Remote-IP", "X-Remote-Addr", "True-Client-IP", "CF-Connecting-IP",
    "X-Forwarded", "Forwarded",
]

# Values that commonly appear in an app's own "trusted" allowlist logic.
SPOOF_VALUES = ["127.0.0.1", "localhost", "10.0.0.1", "192.168.0.1", "0.0.0.0"]

FALLBACK_PATHS = [
    "/admin", "/admin/", "/administrator", "/manager", "/manager/html",
    "/dashboard", "/internal", "/private", "/management", "/console",
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


def read_json(path, default=None):
    if not os.path.isfile(path):
        return default
    try:
        with open(path, "r", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return default


def collect_candidate_paths(hosts):
    """Returns a list of (host, path) tuples worth testing — prefers paths
    already confirmed as 401/403 by earlier steps, falls back to a short
    curated list per host if none were found."""
    candidates = []

    sensitive = read_json("report/sensitive_files.json", {}) or {}
    for f in sensitive.get("findings", []):
        if f.get("status") in (401, 403) and f.get("host") and f.get("path"):
            candidates.append((f["host"], f["path"]))

    content_disc = read_json("report/content_discovery.json", {}) or {}
    for f in content_disc.get("findings", []):
        if f.get("status") in (401, 403) and f.get("url"):
            parsed = urlparse(f["url"])
            host = f"{parsed.scheme}://{parsed.netloc}"
            path = parsed.path or "/"
            candidates.append((host, path))

    if not candidates:
        for host in hosts:
            for path in FALLBACK_PATHS:
                candidates.append((host, path))

    seen = set()
    deduped = []
    for host, path in candidates:
        key = (host, path)
        if key not in seen:
            seen.add(key)
            deduped.append(key)
    return deduped


def test_bypass(host_path):
    host, path = host_path
    url = host + path
    findings = []

    try:
        baseline = get(url, timeout=TIMEOUT, verify=False, allow_redirects=False)
    except Exception:
        return findings
    if baseline.status_code not in (401, 403):
        return findings  # nothing restricted here, nothing to bypass

    for header in SPOOF_HEADERS:
        for value in SPOOF_VALUES:
            try:
                r = get(url, headers={header: value}, timeout=TIMEOUT, verify=False, allow_redirects=False)
            except Exception:
                continue
            if r.status_code not in (401, 403) and r.status_code != baseline.status_code:
                findings.append({
                    "url": url,
                    "baseline_status": baseline.status_code,
                    "bypass_header": header,
                    "bypass_value": value,
                    "bypassed_status": r.status_code,
                })
                break  # one confirmed bypass per path is enough signal; move on
        if findings:
            break

    return findings


def main():
    hosts = read_hosts()
    candidates = collect_candidate_paths(hosts)
    all_findings = []

    if candidates:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            for i, result in enumerate(ex.map(test_bypass, candidates), 1):
                all_findings.extend(result)
                print(f"\r  testing IP-restriction bypass  {i}/{len(candidates)}   ", end="", flush=True)
    print("")

    os.makedirs("report", exist_ok=True)
    summary = {
        "candidates_tested": len(candidates),
        "bypasses_found": len(all_findings),
        "findings": all_findings,
    }
    with open("report/ip_bypass.json", "w") as f:
        json.dump(summary, f, indent=2)

    with open("report/ip_bypass.txt", "w") as f:
        f.write(f"Restricted paths tested: {len(candidates)}\n")
        f.write(f"IP-restriction bypasses confirmed: {len(all_findings)}\n\n")
        for finding in all_findings:
            f.write(f"[BYPASS] {finding['url']}\n")
            f.write(f"    baseline: {finding['baseline_status']}  ->  bypassed: {finding['bypassed_status']}\n")
            f.write(f"    via header: {finding['bypass_header']}: {finding['bypass_value']}\n\n")

    print(f"  ✓ IP bypass check: {len(all_findings)} confirmed bypass(es) out of {len(candidates)} restricted paths tested -> report/ip_bypass.*")


if __name__ == "__main__":
    main()
