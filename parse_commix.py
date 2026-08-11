#!/usr/bin/env python3
"""
parse_commix.py

commix (COMMand Injection eXploiter) is run in DETECTION mode by
recon-framework.sh, once per parameterized URL:
    commix --url="<url>" --batch --level=1
--level=1 is commix's least invasive testing level. This step confirms
whether a parameter IS vulnerable to OS command injection — it does not
attempt to open a shell, read files, or otherwise act on a confirmed
vulnerability. Same "detect, don't exploit" posture as the sqlmap step.

Since recon-framework.sh runs commix once per URL (commix has no built-in
bulk/file-list mode like sqlmap's -m), each log file in cmdi/ corresponds
to exactly one URL — the URL is recovered directly from the log's filename
(reversing the same sanitization used to create it), so this parser doesn't
need to guess at output structure to know which URL a finding belongs to.

commix's own reporting format has varied across versions, so detection here
is intentionally loose: any log containing "vulnerable" (case-insensitive)
is treated as a hit, with parameter/technique/type/payload extracted on a
best-effort basis from nearby "Parameter:"/"Technique:"/"Type:"/"Payload:"
style lines if present. Raw logs are always preserved in cmdi/ for manual
review regardless of what this parser manages to extract.

Reads:  cmdi/commix_*.log, params/urls_with_params.txt
Writes: report/cmdi_findings.json
        report/cmdi_findings.txt
"""
import os
import re
import glob
import json

VULN_RE = re.compile(r"vulnerable", re.I)
PARAM_RE = re.compile(r"[Pp]arameter[:\s]+'?([A-Za-z0-9_\[\]]+)'?")
TECHNIQUE_RE = re.compile(r"Technique\s*:\s*(.+)")
TYPE_RE = re.compile(r"^\s*Type\s*:\s*(.+)$", re.M)
PAYLOAD_RE = re.compile(r"(?:Injection payload|Payload)\s*:\s*(.+)")


def sanitize(url):
    return re.sub(r"[^a-zA-Z0-9]", "_", url)


def read_lines(path):
    if not os.path.isfile(path):
        return []
    with open(path, "r", errors="ignore") as f:
        return [l.strip() for l in f if l.strip()]


def main():
    urls = read_lines("params/urls_with_params.txt")
    url_by_safe = {sanitize(u): u for u in urls}

    findings = []
    logs_checked = 0
    for path in sorted(glob.glob("cmdi/commix_*.log")):
        logs_checked += 1
        fname = os.path.basename(path)
        safe = fname[len("commix_"):-len(".log")] if fname.startswith("commix_") else fname[:-4]
        url = url_by_safe.get(safe, safe)

        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
        except Exception:
            continue

        if not VULN_RE.search(content):
            continue

        param_match = PARAM_RE.search(content)
        technique_match = TECHNIQUE_RE.search(content)
        type_match = TYPE_RE.search(content)
        payload_match = PAYLOAD_RE.search(content)

        findings.append({
            "url": url,
            "parameter": param_match.group(1) if param_match else None,
            "technique": technique_match.group(1).strip() if technique_match else None,
            "type": type_match.group(1).strip() if type_match else None,
            "payload": payload_match.group(1).strip() if payload_match else None,
            "log_file": path,
        })

    os.makedirs("report", exist_ok=True)
    summary = {
        "logs_checked": logs_checked,
        "confirmed_injections": len(findings),
        "findings": findings,
    }
    with open("report/cmdi_findings.json", "w") as f:
        json.dump(summary, f, indent=2)

    with open("report/cmdi_findings.txt", "w") as f:
        f.write(f"URLs tested: {logs_checked}\n")
        f.write(f"Confirmed command injection points: {len(findings)}\n")
        f.write("(Detection-only run: --level=1, no shell/file-read/exfiltration attempted.\n")
        f.write(" Raw commix logs preserved in cmdi/ for manual follow-up.)\n\n")
        for finding in findings:
            f.write(f"[INJECTABLE] {finding['url']}\n")
            if finding.get("parameter"):
                f.write(f"    parameter: {finding['parameter']}\n")
            if finding.get("technique"):
                f.write(f"    technique: {finding['technique']}\n")
            if finding.get("type"):
                f.write(f"    type: {finding['type']}\n")
            if finding.get("payload"):
                f.write(f"    payload: {finding['payload']}\n")
            f.write(f"    raw log: {finding['log_file']}\n\n")

    print(f"  ✓ Command injection detection: {len(findings)} confirmed point(s) out of "
          f"{logs_checked} URL(s) tested -> report/cmdi_findings.*")


if __name__ == "__main__":
    main()
