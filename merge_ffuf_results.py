#!/usr/bin/env python3
"""
merge_ffuf_results.py

Merges the per-host content-discovery output from BOTH tools used in that
step (produced one file per host):
  - ffuf_*.json       (ffuf, JSON format)
  - dirsearch_*.txt   (dirsearch, --format=plain — stable across versions,
                        unlike its JSON schema which varies by fork/release)

into a single consolidated report. Findings from both tools are deduped by
URL, keeping a note of which tool(s) found it — a path flagged by both is
a stronger signal.

Reads:  ffuf_*.json, dirsearch_*.txt (in the current directory — content_discovery/)
Writes: ../report/content_discovery.json
        ../report/content_discovery.txt

Usage: run from inside content_discovery/ (recon-framework.sh does this automatically)
    python3 ../merge_ffuf_results.py
"""
import os
import re
import json
import glob

DIRSEARCH_LINE_RE = re.compile(r"^\[\d{2}:\d{2}:\d{2}\]\s+(\d{3})\s+-\s+(\S+)\s+-\s+(\S+)")


def parse_ffuf_files():
    findings = []
    for fname in glob.glob("ffuf_*.json"):
        try:
            with open(fname, "r", errors="ignore") as f:
                data = json.load(f)
        except Exception:
            continue
        for r in data.get("results", []):
            findings.append({
                "url": r.get("url"),
                "status": r.get("status"),
                "length": r.get("length"),
                "source": "ffuf",
            })
    return findings


def parse_dirsearch_files():
    findings = []
    for fname in glob.glob("dirsearch_*.txt"):
        try:
            with open(fname, "r", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            continue
        for line in lines:
            m = DIRSEARCH_LINE_RE.match(line.strip())
            if not m:
                continue
            status, size, path = m.groups()
            findings.append({
                "url": path,
                "status": int(status),
                "length": size,
                "source": "dirsearch",
            })
    return findings


def dedup(findings):
    merged = {}
    for f in findings:
        key = f.get("url")
        if not key:
            continue
        if key not in merged:
            merged[key] = {**f, "sources": [f["source"]]}
        elif f["source"] not in merged[key]["sources"]:
            merged[key]["sources"].append(f["source"])
    for v in merged.values():
        v.pop("source", None)
    return list(merged.values())


def main():
    all_findings = dedup(parse_ffuf_files() + parse_dirsearch_files())

    os.makedirs("../report", exist_ok=True)

    with open("../report/content_discovery.json", "w") as f:
        json.dump({"total_findings": len(all_findings), "findings": all_findings}, f, indent=2)

    with open("../report/content_discovery.txt", "w") as f:
        f.write(f"Total discovered paths: {len(all_findings)}\n")
        f.write("(ffuf auto-calibration + dirsearch already filtered obvious soft-404s)\n\n")
        for r in sorted(all_findings, key=lambda x: x.get("url") or ""):
            sources = "+".join(r.get("sources", []))
            f.write(f"[{r.get('status')}] {r.get('url')}  ({r.get('length')} bytes) <{sources}>\n")

    print(f"  ✓ Content discovery merged: {len(all_findings)} unique path(s) found -> report/content_discovery.*")


if __name__ == "__main__":
    main()