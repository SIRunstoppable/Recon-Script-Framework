#!/usr/bin/env python3
"""
parse_nikto.py

Nikto (a classic web server vulnerability/misconfiguration scanner —
dangerous files, outdated server banners, multiple index files, common
CGI/admin paths, etc.) is run once per live host by recon-framework.sh,
each writing its own text report to nikto/nikto_<host>.txt. This script
merges them into one consolidated, structured report.

Nikto's text output is a loosely-structured "+ <finding>" line format that
varies a bit by version, so this parser stays intentionally simple: it
keeps every "+ " line that isn't known scan metadata (target IP/hostname/
port, start/end time, server banner-only line, summary counts).

Reads:  nikto/nikto_*.txt
Writes: report/nikto.json
        report/nikto.txt
"""
import os
import re
import glob
import json

METADATA_PREFIXES = (
    "+ Target IP:", "+ Target Hostname:", "+ Target Port:",
    "+ Start Time:", "+ End Time:", "+ Multiple IPs found",
)
SUMMARY_RE = re.compile(r"^\+ \d+ (host|error|item)")


def parse_file(path):
    findings = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.startswith("+ "):
                continue
            if line.startswith(METADATA_PREFIXES):
                continue
            if SUMMARY_RE.match(line):
                continue
            findings.append(line[2:].strip())
    return findings


def host_from_filename(fname):
    # nikto_http___example_com.txt -> best-effort readable label
    base = os.path.basename(fname)
    base = base[len("nikto_"):-len(".txt")] if base.startswith("nikto_") else base
    return base.replace("_", ".")


def main():
    files = sorted(glob.glob("nikto/nikto_*.txt"))
    results = []
    for path in files:
        findings = parse_file(path)
        if findings:
            results.append({"host_label": host_from_filename(path), "source_file": path, "findings": findings})

    os.makedirs("report", exist_ok=True)
    total_findings = sum(len(r["findings"]) for r in results)

    with open("report/nikto.json", "w") as f:
        json.dump({"hosts_scanned": len(files), "total_findings": total_findings, "results": results}, f, indent=2)

    with open("report/nikto.txt", "w") as f:
        f.write(f"Hosts scanned: {len(files)}\n")
        f.write(f"Total findings: {total_findings}\n\n")
        for r in results:
            f.write(f"[{r['host_label']}] ({len(r['findings'])} findings)\n")
            for finding in r["findings"]:
                f.write(f"    {finding}\n")
            f.write("\n")

    print(f"  ✓ Nikto scan: {total_findings} finding(s) across {len(files)} host(s) -> report/nikto.*")


if __name__ == "__main__":
    main()
