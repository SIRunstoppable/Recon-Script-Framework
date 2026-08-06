#!/usr/bin/env python3
"""
parse_sqlmap.py

sqlmap is run in DETECTION-ONLY mode by recon-framework.sh:
    sqlmap -m params/urls_with_params.txt --batch --level=1 --risk=1 ...
--level=1 --risk=1 is sqlmap's least invasive setting (fastest, safest —
no time-based/heavy payloads). Critically, this invocation never includes
--dump, --os-shell, --sql-shell, or any enumeration/exploitation flag — it
only confirms whether a parameter IS injectable, the same "detect, don't
exploit" posture as every other check in this pipeline (e.g. the IP-bypass
check confirms a bypass exists without doing anything with the resulting
access).

sqlmap's own log output format is verbose and has changed a bit across
versions, so this parser stays defensive: it tracks the most recently seen
target URL, and whenever it sees a "Parameter: ... (METHOD)" block (sqlmap's
standard way of reporting a confirmed injection point) it records the
associated injection types/payloads found directly beneath it, plus any
"back-end DBMS" line found nearby. If sqlmap's output format has changed
enough that this parser finds nothing, the raw log itself is preserved at
logs/sqlmap.log for manual review — this parser is a convenience layer,
not the source of truth.

Reads:  logs/sqlmap.log
Writes: report/sqli_findings.json
        report/sqli_findings.txt
"""
import os
import re
import json

LOG_PATH = "logs/sqlmap.log"

URL_CONTEXT_RE = re.compile(r"(?:testing URL|resuming URL|URL)\s*'?(https?://[^\s'\"]+)")
PARAM_HEADER_RE = re.compile(r"^Parameter:\s*(\S+)\s*\(([^)]+)\)")
TYPE_RE = re.compile(r"^\s*Type:\s*(.+)$")
TITLE_RE = re.compile(r"^\s*Title:\s*(.+)$")
PAYLOAD_RE = re.compile(r"^\s*Payload:\s*(.+)$")
DBMS_RE = re.compile(r"back-end DBMS:\s*(.+)$", re.I)
NOT_INJECTABLE_RE = re.compile(r"do(?:es)? not appear to be injectable", re.I)


def parse_log(path):
    if not os.path.isfile(path):
        return [], False

    findings = []
    current_url = None
    current_dbms = None
    current_param = None  # {"parameter":..., "method":..., "types":[...]}
    saw_any_activity = False

    with open(path, "r", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue
            saw_any_activity = True

            m = URL_CONTEXT_RE.search(line)
            if m:
                current_url = m.group(1)
                continue

            m = DBMS_RE.search(line)
            if m:
                current_dbms = m.group(1).strip()
                continue

            m = PARAM_HEADER_RE.match(line)
            if m:
                if current_param:
                    findings.append(current_param)
                current_param = {
                    "url": current_url,
                    "parameter": m.group(1),
                    "method": m.group(2),
                    "dbms": current_dbms,
                    "types": [],
                }
                continue

            if current_param:
                m = TYPE_RE.match(line)
                if m:
                    current_param["types"].append({"type": m.group(1).strip()})
                    continue
                m = TITLE_RE.match(line)
                if m and current_param["types"]:
                    current_param["types"][-1]["title"] = m.group(1).strip()
                    continue
                m = PAYLOAD_RE.match(line)
                if m and current_param["types"]:
                    current_param["types"][-1]["payload"] = m.group(1).strip()
                    continue

    if current_param:
        findings.append(current_param)

    return findings, saw_any_activity


def main():
    findings, saw_activity = parse_log(LOG_PATH)

    os.makedirs("report", exist_ok=True)
    summary = {
        "sqlmap_log_found": os.path.isfile(LOG_PATH),
        "confirmed_injections": len(findings),
        "findings": findings,
    }
    with open("report/sqli_findings.json", "w") as f:
        json.dump(summary, f, indent=2)

    with open("report/sqli_findings.txt", "w") as f:
        f.write(f"Confirmed SQL injection points: {len(findings)}\n")
        f.write("(Detection-only run: --level=1 --risk=1, no data extraction attempted.\n")
        f.write(f" Raw sqlmap output preserved at {LOG_PATH} for manual follow-up.)\n\n")
        for finding in findings:
            f.write(f"[INJECTABLE] {finding.get('url') or 'unknown URL'}\n")
            f.write(f"    parameter: {finding['parameter']} ({finding['method']})\n")
            if finding.get("dbms"):
                f.write(f"    back-end DBMS: {finding['dbms']}\n")
            for t in finding["types"]:
                f.write(f"    - {t.get('type','?')}: {t.get('title','')}\n")
                if t.get("payload"):
                    f.write(f"      payload: {t['payload']}\n")
            f.write("\n")
        if not findings and not saw_activity:
            f.write("(sqlmap did not run, or its log format was not recognized by this parser —\n"
                    f" check {LOG_PATH} directly if sqlmap was expected to run.)\n")

    print(f"  ✓ SQLi detection: {len(findings)} confirmed injection point(s) -> report/sqli_findings.*")


if __name__ == "__main__":
    main()
