#!/usr/bin/env python3
"""
check_sensitive_files.py

For every live host, probes a curated list of commonly-exposed sensitive
paths (.git/HEAD, .env, backups, cloud creds, swagger, actuator, etc).

False-positive guard: many sites return HTTP 200 with a custom "not found"
page for *any* path (soft-404). Before checking real paths, this script
requests one random nonexistent path per host as a baseline and skips any
result that matches the baseline's status code + response length — that's
almost always a soft-404, not a real hit.

Reads:  live/httpx_live.txt
Writes: report/sensitive_files.json
        report/sensitive_files.txt

Usage: run from WORKDIR root (same level as live/, report/)
    python3 check_sensitive_files.py

Requires: requests (pip install requests --break-system-packages)
"""
import os
import json
import random
import string
import concurrent.futures

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("  ⚠ 'requests' not installed — skipping sensitive file check.")
    print("    pip install requests --break-system-packages")
    raise SystemExit(0)

from rate_limiter import get, MAX_WORKERS

TIMEOUT = 6

SENSITIVE_PATHS = [
    # VCS
    "/.git/HEAD", "/.git/config", "/.git/logs/HEAD", "/.svn/entries", "/.hg/store/",
    # env / secrets
    "/.env", "/.env.local", "/.env.production", "/.env.bak", "/.aws/credentials",
    "/id_rsa", "/id_rsa.pub", "/.ssh/id_rsa", "/.htpasswd",
    # backups / dumps
    "/backup.zip", "/backup.sql", "/backup.tar.gz", "/dump.sql", "/database.sql",
    "/db_backup.sql", "/site-backup.zip",
    # config / infra
    "/wp-config.php.bak", "/wp-config.php~", "/config.php.bak", "/config.php~",
    "/docker-compose.yml", "/docker-compose.yaml", "/Dockerfile", "/web.config",
    "/composer.json", "/package.json", "/.idea/workspace.xml", "/.vscode/sftp.json",
    # debug / info disclosure
    "/phpinfo.php", "/info.php", "/server-status", "/server-info",
    "/actuator/health", "/actuator/env", "/actuator", "/debug/vars",
    # API / admin surfaces
    "/swagger.json", "/swagger-ui.html", "/api/swagger.json", "/api-docs",
    "/graphql", "/graphiql", "/admin/", "/administrator/", "/manager/html",
    "/.well-known/security.txt",
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


def get_baseline(host):
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
    try:
        r = get(f"{host}/__nonexistent_{rand}__", timeout=TIMEOUT, verify=False, allow_redirects=False)
        return r.status_code, len(r.content)
    except Exception:
        return None, None


def check_host(host):
    findings = []
    base_status, base_len = get_baseline(host)
    for path in SENSITIVE_PATHS:
        try:
            r = get(host + path, timeout=TIMEOUT, verify=False, allow_redirects=False)
        except Exception:
            continue
        status = r.status_code
        length = len(r.content)

        if status == 404:
            continue
        # matches the soft-404 baseline for this host -> not a real hit
        if base_status is not None and status == base_status and abs(length - (base_len or 0)) < 15:
            continue
        if status in (200, 201, 206) or status in (401, 403):
            findings.append({
                "host": host,
                "path": path,
                "url": host + path,
                "status": status,
                "length": length,
                "note": "confirmed accessible" if status < 300 else "exists but protected (auth required)",
            })
    return findings


def main():
    hosts = read_hosts()
    all_findings = []

    if hosts:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            for i, result in enumerate(ex.map(check_host, hosts), 1):
                all_findings.extend(result)
                print(f"\r  scanning hosts for sensitive files  {i}/{len(hosts)}   ", end="", flush=True)
    print("")

    os.makedirs("report", exist_ok=True)
    accessible = [f for f in all_findings if f["status"] < 300]
    protected = [f for f in all_findings if f["status"] >= 300]

    summary = {
        "hosts_scanned": len(hosts),
        "total_findings": len(all_findings),
        "accessible_count": len(accessible),
        "protected_count": len(protected),
        "findings": all_findings,
    }
    with open("report/sensitive_files.json", "w") as f:
        json.dump(summary, f, indent=2)

    with open("report/sensitive_files.txt", "w") as f:
        f.write(f"Hosts scanned: {len(hosts)}\n")
        f.write(f"Total findings: {len(all_findings)} "
                f"({len(accessible)} directly accessible, {len(protected)} exist but protected)\n\n")
        if accessible:
            f.write("=== DIRECTLY ACCESSIBLE (HIGH PRIORITY) ===\n")
            for x in accessible:
                f.write(f"[{x['status']}] {x['url']}  ({x['length']} bytes)\n")
            f.write("\n")
        if protected:
            f.write("=== EXISTS BUT PROTECTED (auth required) ===\n")
            for x in protected:
                f.write(f"[{x['status']}] {x['url']}\n")

    print(f"  ✓ Sensitive file check: {len(accessible)} directly accessible, "
          f"{len(protected)} protected -> report/sensitive_files.*")


if __name__ == "__main__":
    main()
