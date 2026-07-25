#!/usr/bin/env python3
"""
merge_ffuf_results.py

Merges the per-host ffuf JSON output files (produced by the Content
Discovery step, one file per live host) into a single consolidated report.

Reads:  ffuf_*.json (in the current directory — content_discovery/)
Writes: ../report/content_discovery.json
        ../report/content_discovery.txt

Usage: run from inside content_discovery/ (recon-framework.sh does this automatically)
    python3 ../merge_ffuf_results.py
"""
import os
import json
import glob


def main():
    all_findings = []
    for fname in glob.glob("ffuf_*.json"):
        try:
            with open(fname, "r", errors="ignore") as f:
                data = json.load(f)
        except Exception:
            continue
        for r in data.get("results", []):
            all_findings.append({
                "url": r.get("url"),
                "status": r.get("status"),
                "length": r.get("length"),
                "words": r.get("words"),
            })

    os.makedirs("../report", exist_ok=True)

    with open("../report/content_discovery.json", "w") as f:
        json.dump({"total_findings": len(all_findings), "findings": all_findings}, f, indent=2)

    with open("../report/content_discovery.txt", "w") as f:
        f.write(f"Total discovered paths: {len(all_findings)}\n")
        f.write("(ffuf auto-calibration already filtered soft-404 / custom-not-found pages)\n\n")
        for r in sorted(all_findings, key=lambda x: x.get("url") or ""):
            f.write(f"[{r.get('status')}] {r.get('url')}  ({r.get('length')} bytes)\n")

    print(f"  ✓ Content discovery merged: {len(all_findings)} path(s) found -> report/content_discovery.*")


if __name__ == "__main__":
    main()
