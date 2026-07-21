#!/usr/bin/env python3
"""
wordpress_scan.py

Detects WordPress among the live hosts (via httpx's tech-detect output plus
active confirmation), then checks a handful of WordPress-specific low-hanging
fruit:

  - Version disclosure via /readme.html
  - Username enumeration via the public /wp-json/wp/v2/users REST endpoint
    (enabled by default on most WordPress installs)
  - xmlrpc.php reachability (used for login brute-force amplification and
    pingback-based DDoS/SSRF if enabled)

Confirmed WordPress hosts are written to wordpress/wp_hosts.txt so the shell
script can run nuclei's WordPress-specific templates (core/plugin/theme CVEs)
against exactly those hosts instead of the whole target list.

Reads:  live/httpx_live.txt
Writes: wordpress/wp_hosts.txt
        report/wordpress.json
        report/wordpress.txt

Usage: run from WORKDIR root
    python3 wordpress_scan.py

Requires: requests (pip install requests --break-system-packages)
"""
import os
import re
import json
import concurrent.futures

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("  ⚠ 'requests' not installed — skipping WordPress scan.")
    print("    pip install requests --break-system-packages")
    raise SystemExit(0)

TIMEOUT = 8
MAX_WORKERS = 15


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
                hosts.append((url.rstrip("/"), line))
    return hosts


def looks_like_wp_from_techline(line):
    return "wordpress" in line.lower()


def confirm_wp(host):
    indicators = []
    try:
        r = requests.get(f"{host}/wp-login.php", timeout=TIMEOUT, verify=False, allow_redirects=True)
        if r.status_code in (200, 403) and ("wp-login" in r.text.lower() or "wordpress" in r.text.lower()):
            indicators.append("wp-login.php")
    except Exception:
        pass
    try:
        r = requests.get(f"{host}/wp-json/", timeout=TIMEOUT, verify=False)
        if r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, dict) and ("namespaces" in data or "name" in data):
                    indicators.append("wp-json REST API")
            except Exception:
                pass
    except Exception:
        pass
    return indicators


def get_wp_version(host):
    try:
        r = requests.get(f"{host}/readme.html", timeout=TIMEOUT, verify=False)
        if r.status_code == 200:
            m = re.search(r"[Vv]ersion\s+([\d.]+)", r.text)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


def enum_users(host):
    users = []
    try:
        r = requests.get(f"{host}/wp-json/wp/v2/users", timeout=TIMEOUT, verify=False)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list):
                for u in data:
                    if isinstance(u, dict) and u.get("slug"):
                        users.append(u.get("slug"))
    except Exception:
        pass
    return users


def check_xmlrpc(host):
    try:
        r = requests.get(f"{host}/xmlrpc.php", timeout=TIMEOUT, verify=False)
        return r.status_code == 200 and "xml-rpc" in r.text.lower()
    except Exception:
        return False


def process(host_line):
    host, raw_line = host_line
    tech_flagged = looks_like_wp_from_techline(raw_line)
    indicators = confirm_wp(host)
    if not tech_flagged and not indicators:
        return None
    return {
        "host": host,
        "detected_via_tech_scan": tech_flagged,
        "indicators": indicators,
        "version": get_wp_version(host),
        "enumerated_usernames": enum_users(host),
        "xmlrpc_enabled": check_xmlrpc(host),
    }


def main():
    hosts = read_hosts()
    results = []

    if hosts:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            for i, res in enumerate(ex.map(process, hosts), 1):
                if res:
                    results.append(res)
                print(f"\r  checking for WordPress  {i}/{len(hosts)}   ", end="", flush=True)
    print("")

    os.makedirs("wordpress", exist_ok=True)
    os.makedirs("report", exist_ok=True)

    with open("wordpress/wp_hosts.txt", "w") as f:
        for r in results:
            f.write(r["host"] + "\n")

    summary = {"hosts_scanned": len(hosts), "wordpress_hosts_found": len(results), "sites": results}
    with open("report/wordpress.json", "w") as f:
        json.dump(summary, f, indent=2)

    with open("report/wordpress.txt", "w") as f:
        f.write(f"Hosts scanned: {len(hosts)}\n")
        f.write(f"WordPress sites detected: {len(results)}\n\n")
        for r in results:
            f.write(f"[{r['host']}]\n")
            f.write(f"  version: {r['version'] or 'unknown (not disclosed via readme.html)'}\n")
            f.write(f"  confirmation: {', '.join(r['indicators']) or 'tech-detect only'}\n")
            f.write(f"  xmlrpc.php reachable: {r['xmlrpc_enabled']}\n")
            if r["enumerated_usernames"]:
                f.write(f"  usernames enumerated via /wp-json/wp/v2/users: {', '.join(r['enumerated_usernames'])}\n")
            f.write("\n")

    print(f"  ✓ WordPress scan: {len(results)} site(s) detected -> wordpress/wp_hosts.txt, report/wordpress.*")


if __name__ == "__main__":
    main()
