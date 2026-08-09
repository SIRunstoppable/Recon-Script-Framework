#!/usr/bin/env python3
"""
fingerprint_waf.py

Identifies which WAF/CDN (if any) protects each live host. This is purely
informational — knowing what's in front of a target is standard recon and
useful for the report (e.g. "this host is behind Cloudflare" explains why
certain scans came back thin). Nothing here is designed to evade, bypass,
or get payloads past whatever WAF is detected — it only identifies it.

Two independent detection methods, results merged:

  1. wafw00f (if installed) — the standard open-source WAF fingerprinting
     tool, run once per host by recon-framework.sh with -a (report every
     matching signature, not just the first). This script parses its text
     output.

  2. A lightweight built-in fallback — a single plain GET request per host,
     checking the response headers against signatures for ~10 of the most
     common WAF/CDN providers (Cloudflare, Akamai, Sucuri, Imperva/Incapsula,
     AWS CloudFront, Azure Front Door, F5 BIG-IP ASM, Fortinet FortiWeb,
     Barracuda, generic ModSecurity/Citrix). Runs regardless of whether
     wafw00f is installed, so this step is never a total no-op.

Reads:  live/httpx_live.txt, waf/wafw00f_*.txt (if wafw00f ran)
Writes: report/waf_detection.json
        report/waf_detection.txt
"""
import os
import re
import glob
import json

try:
    from rate_limiter import get
except ImportError:
    get = None

TIMEOUT = 8

WAFW00F_MATCH_RE = re.compile(r"is behind\s+(.+?)\s*\((.+?)\)\s*WAF", re.I)
WAFW00F_NONE_RE = re.compile(r"No WAF detected", re.I)

# (header name, required substring in its value or None for "header just needs to exist", label)
WAF_HEADER_SIGNATURES = [
    ("server", "cloudflare", "Cloudflare"),
    ("cf-ray", None, "Cloudflare"),
    ("server", "akamaighost", "Akamai"),
    ("server", "sucuri", "Sucuri CloudProxy"),
    ("x-sucuri-id", None, "Sucuri CloudProxy"),
    ("server", "bigip", "F5 BIG-IP ASM"),
    ("x-cdn", "incapsula", "Imperva Incapsula"),
    ("x-iinfo", None, "Imperva Incapsula"),
    ("server", "cloudfront", "Amazon CloudFront"),
    ("x-amz-cf-id", None, "Amazon CloudFront"),
    ("x-azure-ref", None, "Azure Front Door"),
    ("server", "fortiweb", "Fortinet FortiWeb"),
    ("server", "barracudawaf", "Barracuda WAF"),
    ("server", "mod_security", "ModSecurity"),
    ("server", "nsc_", "Citrix NetScaler"),
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


def parse_wafw00f_files():
    """Maps host -> list of {"name":..., "vendor":...} from wafw00f's text output."""
    results = {}
    for path in glob.glob("waf/wafw00f_*.txt"):
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
        except Exception:
            continue
        host_match = re.search(r"Checking\s+(\S+)", content)
        host = host_match.group(1).rstrip("/") if host_match else os.path.basename(path)
        matches = WAFW00F_MATCH_RE.findall(content)
        if matches:
            results[host] = [{"name": name.strip(), "vendor": vendor.strip()} for name, vendor in matches]
        elif WAFW00F_NONE_RE.search(content):
            results[host] = []
    return results


def header_fingerprint(host):
    if not get:
        return []
    try:
        r = get(host, timeout=TIMEOUT, verify=False, allow_redirects=True)
    except Exception:
        return []
    headers = {k.lower(): (v or "") for k, v in r.headers.items()}
    found = []
    for header_name, needle, label in WAF_HEADER_SIGNATURES:
        if header_name in headers:
            value = headers[header_name].lower()
            if needle is None or needle in value:
                if not any(f["name"] == label for f in found):
                    found.append({"name": label, "vendor": None, "detected_via": f"header:{header_name}"})
    return found


def main():
    hosts = read_hosts()
    wafw00f_results = parse_wafw00f_files()

    combined = {}
    for host in hosts:
        detections = []
        for d in wafw00f_results.get(host, []):
            detections.append({**d, "detected_via": "wafw00f"})
        for d in header_fingerprint(host):
            if not any(x["name"] == d["name"] for x in detections):
                detections.append(d)
        if detections:
            combined[host] = detections

    os.makedirs("report", exist_ok=True)
    protected_hosts = list(combined.keys())

    summary = {
        "hosts_scanned": len(hosts),
        "protected_hosts_count": len(protected_hosts),
        "detections": combined,
    }
    with open("report/waf_detection.json", "w") as f:
        json.dump(summary, f, indent=2)

    with open("report/waf_detection.txt", "w") as f:
        f.write(f"Hosts scanned: {len(hosts)}\n")
        f.write(f"Hosts with a detected WAF/CDN: {len(protected_hosts)}\n\n")
        for host, detections in combined.items():
            names = ", ".join(f"{d['name']}{' (' + d['vendor'] + ')' if d.get('vendor') else ''}" for d in detections)
            f.write(f"{host}: {names}\n")
        unprotected = [h for h in hosts if h not in combined]
        if unprotected:
            f.write(f"\nNo WAF/CDN detected on {len(unprotected)} host(s):\n")
            for h in unprotected:
                f.write(f"  {h}\n")

    print(f"  ✓ WAF detection: {len(protected_hosts)}/{len(hosts)} host(s) behind a detected WAF/CDN -> report/waf_detection.*")


if __name__ == "__main__":
    main()
