#!/usr/bin/env python3
"""
check_shodan.py <domain>

Shodan-based asset discovery, scoped STRICTLY to the authorized target:
  - hostname:<domain>   — assets whose indexed hostname matches/contains the domain
  - ssl:<domain>         — assets serving a TLS cert for the domain (catches
                            IPs that don't show up in hostname search, e.g.
                            behind a different reverse-DNS entry)

These are not broad/unscoped searches — every result returned genuinely
matches the target's own domain or certificate, same scoping principle as
every other active step in this pipeline.

For every matched asset, Shodan's host-search response already includes a
`vulns` field listing any CVEs its own vulnerability database has already
correlated with that host's banner (this is Shodan's own data — nothing is
actively exploited or even actively scanned by this script; it's a lookup
against an index). Assets with known CVEs are sorted first and highlighted,
since those are the most actionable leads for follow-up manual testing.

Also merges any newly-seen hostnames back into all_subdomains.txt, since
Shodan often indexes subdomains that active enumeration tools miss (e.g.
because they're not in a wordlist and don't show up in certificate
transparency logs).

Requires a Shodan API key (SHODAN_API_KEY in .env — get one at
https://account.shodan.io/). The host-search endpoint consumes query
credits; free-tier keys have limited monthly credits, so this script only
issues 2 queries per run.

Reads:  domain (argv)
Writes: report/shodan.json
        report/shodan.txt
        appends newly-discovered hostnames to all_subdomains.txt

Usage: run from WORKDIR root
    python3 check_shodan.py <domain>
"""
import os
import sys
import json
import time

try:
    from rate_limiter import get
except ImportError:
    print("  ⚠ rate_limiter.py not found next to this script — skipping Shodan check.")
    raise SystemExit(0)

API_BASE = "https://api.shodan.io"
TIMEOUT = 15


def shodan_search(query, api_key):
    try:
        r = get(f"{API_BASE}/shodan/host/search", params={"key": api_key, "query": query}, timeout=TIMEOUT)
    except Exception as e:
        return None, str(e)
    if r.status_code == 401:
        return None, "invalid/unauthorized Shodan API key"
    if r.status_code == 403:
        return None, "API key lacks search credits (host search requires a paid/upgraded Shodan plan)"
    if r.status_code != 200:
        return None, f"HTTP {r.status_code}: {r.text[:200]}"
    try:
        return r.json(), None
    except Exception:
        return None, "invalid JSON response"


def merge_new_hostnames(hostnames, domain):
    """Appends any newly-seen subdomains of the target domain into
    all_subdomains.txt, deduping the whole file afterward — same pattern
    as the alterx permutation step."""
    relevant = {h for h in hostnames if h and (h == domain or h.endswith("." + domain))}
    if not relevant:
        return 0
    before = set()
    if os.path.isfile("all_subdomains.txt"):
        with open("all_subdomains.txt", "r", errors="ignore") as f:
            before = {l.strip() for l in f if l.strip()}
    merged = sorted(before | relevant)
    with open("all_subdomains.txt", "w") as f:
        f.write("\n".join(merged) + "\n")
    return len(merged) - len(before)


def main():
    domain = sys.argv[1] if len(sys.argv) > 1 else None
    api_key = os.environ.get("SHODAN_API_KEY", "")

    if not domain:
        print("  ⚠ no domain passed — skipping Shodan check")
        return
    if not api_key:
        print("  ⚠ SHODAN_API_KEY not set in .env — skipping Shodan check")
        print("    get a key at https://account.shodan.io/ (free tier has limited search credits)")
        return

    os.makedirs("report", exist_ok=True)

    queries = [f"hostname:{domain}", f"ssl:{domain}"]
    all_matches = {}
    errors = []

    for q in queries:
        data, err = shodan_search(q, api_key)
        if err:
            errors.append(f"{q}: {err}")
            continue
        for m in data.get("matches", []):
            key = f"{m.get('ip_str')}:{m.get('port')}"
            all_matches.setdefault(key, m)
        time.sleep(1)  # be gentle with query credits

    hosts = []
    all_hostnames = set()
    for m in all_matches.values():
        vulns = m.get("vulns", {}) or {}
        hostnames = m.get("hostnames", []) or []
        all_hostnames.update(hostnames)
        hosts.append({
            "ip": m.get("ip_str"),
            "port": m.get("port"),
            "hostnames": hostnames,
            "org": m.get("org"),
            "product": m.get("product"),
            "banner_snippet": (m.get("data") or "")[:200],
            "known_cves": sorted(vulns.keys()),
            "vuln_count": len(vulns),
        })

    hosts.sort(key=lambda h: -h["vuln_count"])
    vulnerable_hosts = [h for h in hosts if h["vuln_count"] > 0]

    new_subdomain_count = merge_new_hostnames(all_hostnames, domain)

    summary = {
        "domain": domain,
        "queries_run": queries,
        "errors": errors,
        "total_assets_found": len(hosts),
        "assets_with_known_cves": len(vulnerable_hosts),
        "new_subdomains_merged": new_subdomain_count,
        "hosts": hosts,
    }
    with open("report/shodan.json", "w") as f:
        json.dump(summary, f, indent=2)

    with open("report/shodan.txt", "w") as f:
        f.write(f"Domain: {domain}\n")
        f.write(f"Shodan-indexed assets found: {len(hosts)}\n")
        f.write(f"Assets with known CVEs (per Shodan's own vuln database): {len(vulnerable_hosts)}\n")
        f.write(f"New subdomains merged into all_subdomains.txt: {new_subdomain_count}\n")
        if errors:
            f.write(f"Query errors: {'; '.join(errors)}\n")
        f.write("\n")
        if vulnerable_hosts:
            f.write("=== ASSETS WITH KNOWN CVEs (prioritize these) ===\n")
            for h in vulnerable_hosts:
                f.write(f"{h['ip']}:{h['port']}  hostnames={','.join(h['hostnames'])}  product={h['product'] or '?'}\n")
                f.write(f"    CVEs: {', '.join(h['known_cves'])}\n\n")
        f.write("=== ALL ASSETS ===\n")
        for h in hosts:
            f.write(f"{h['ip']}:{h['port']}  hostnames={','.join(h['hostnames'])}  "
                     f"product={h['product'] or '?'}  known_cves={h['vuln_count']}\n")

    print(f"  ✓ Shodan check: {len(hosts)} asset(s) found, {len(vulnerable_hosts)} with known CVEs, "
          f"{new_subdomain_count} new subdomain(s) merged -> report/shodan.*")


if __name__ == "__main__":
    main()
