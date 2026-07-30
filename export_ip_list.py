#!/usr/bin/env python3
"""
export_ip_list.py

Cleans up dnsx's raw '-a -resp' output into a simple, dedicated report of
which real IP address(es) every scanned domain actually resolves to. This
is basic record-keeping (part of documenting exactly what was tested) —
not a WAF/CDN-bypass technique.

Reads:  resolve/domain_ips_raw.txt   (dnsx -a -resp output)
Writes: report/domain_ips.json   {"domain": ["ip1", "ip2", ...], ...}
        report/domain_ips.txt    human-readable "domain -> ip1, ip2" listing
        report/unique_ips.txt    deduped, sorted list of every distinct IP seen

Usage: run from WORKDIR root
    python3 export_ip_list.py
"""
import os
import re
import json

# dnsx -resp output looks like: "sub.example.com [1.2.3.4]" or
# "sub.example.com [1.2.3.4,5.6.7.8]" depending on version/flags.
DNSX_LINE_RE = re.compile(r"^(\S+)\s+\[([^\]]+)\]")

IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def parse_dnsx_output(path):
    domain_ips = {}
    if not os.path.isfile(path):
        return domain_ips
    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = DNSX_LINE_RE.match(line)
            if not m:
                continue
            domain, ip_blob = m.groups()
            ips = [ip.strip() for ip in ip_blob.split(",") if IP_RE.match(ip.strip())]
            if ips:
                domain_ips[domain] = sorted(set(ips))
    return domain_ips


def main():
    domain_ips = parse_dnsx_output("resolve/domain_ips_raw.txt")

    os.makedirs("report", exist_ok=True)

    with open("report/domain_ips.json", "w") as f:
        json.dump(domain_ips, f, indent=2)

    all_ips = sorted({ip for ips in domain_ips.values() for ip in ips})
    with open("report/unique_ips.txt", "w") as f:
        f.write("\n".join(all_ips) + ("\n" if all_ips else ""))

    with open("report/domain_ips.txt", "w") as f:
        f.write(f"Domains resolved: {len(domain_ips)}\n")
        f.write(f"Unique IP addresses: {len(all_ips)}\n\n")
        for domain in sorted(domain_ips.keys()):
            f.write(f"{domain} -> {', '.join(domain_ips[domain])}\n")

    print(f"  ✓ IP export: {len(domain_ips)} domain(s) resolved to {len(all_ips)} unique IP(s) "
          f"-> report/domain_ips.*, report/unique_ips.txt")


if __name__ == "__main__":
    main()
