#!/usr/bin/env python3
"""
collect_flags.py

Final pass over everything already collected: pulls every CRITICAL/HIGH
finding (or otherwise unambiguously dangerous result, like a confirmed
SQL/command injection, even before any explicit severity label) out of
every report/*.json file and consolidates them into one file — so you
don't have to open a dozen separate reports to see what needs urgent
attention.

Makes no new requests and runs no new scans — pure aggregation/summary
over data other steps already produced. Run this LAST (after the
correlation engine), so its output includes the correlation engine's
own cross-referenced findings too.

Sources pulled from: correlations, sqli_findings, cmdi_findings, ip_bypass,
juicy_files, misconfig, cors_headers, cloud_exposure, source_maps,
js_findings, sensitive_files, nuclei_critical.txt.

Reads:  report/*.json, nuclei/nuclei_critical.txt
Writes: report/flags.json
        report/flags.txt
"""
import os
import re
import json

NUCLEI_LINE_RE = re.compile(r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)")
JUICY_HIGH_RISK_EXT = (".env", ".sql", ".db", ".sqlite", ".sqlite3")


def read_json(path, default=None):
    if not os.path.isfile(path):
        return default
    try:
        with open(path, "r", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return default


def read_lines(path):
    if not os.path.isfile(path):
        return []
    with open(path, "r", errors="ignore") as f:
        return [l.strip() for l in f if l.strip()]


def collect():
    flags = []

    for c in (read_json("report/correlations.json", {}) or {}).get("correlations", []):
        if c.get("severity") in ("critical", "high"):
            flags.append({"severity": c["severity"], "source": "correlation_engine",
                          "title": c.get("name"), "detail": c.get("explanation"), "host": c.get("host")})

    for s in (read_json("report/sqli_findings.json", {}) or {}).get("findings", []):
        flags.append({"severity": "critical", "source": "sqlmap", "title": "Confirmed SQL injection",
                      "detail": f"parameter {s.get('parameter')} ({s.get('method')}) — DBMS: {s.get('dbms') or '?'}",
                      "host": s.get("url")})

    for c in (read_json("report/cmdi_findings.json", {}) or {}).get("findings", []):
        flags.append({"severity": "critical", "source": "commix", "title": "Confirmed OS command injection",
                      "detail": f"parameter {c.get('parameter') or '?'}", "host": c.get("url")})

    for b in (read_json("report/ip_bypass.json", {}) or {}).get("findings", []):
        flags.append({"severity": "high", "source": "ip_bypass", "title": "IP-restriction bypass confirmed",
                      "detail": f"{b.get('baseline_status')} -> {b.get('bypassed_status')} via "
                                f"{b.get('bypass_header')}: {b.get('bypass_value')}",
                      "host": b.get("url")})

    for j in (read_json("report/juicy_files.json", {}) or {}).get("files", []):
        if j.get("status") is not None and j.get("status", 999) < 300:
            url_lower = (j.get("url") or "").lower()
            sev = "critical" if url_lower.endswith(JUICY_HIGH_RISK_EXT) else "high"
            flags.append({"severity": sev, "source": "juicy_files", "title": "Exposed backup/config/db file",
                          "detail": f"confirmed accessible (status {j.get('status')})", "host": j.get("url")})

    for m in (read_json("report/misconfig.json", {}) or {}).get("findings", []):
        if m.get("severity") in ("critical", "high"):
            flags.append({"severity": m["severity"], "source": "misconfig", "title": m.get("category"),
                          "detail": m.get("detail") or m.get("response_preview", ""), "host": m.get("host")})

    for c in (read_json("report/cors_headers.json", {}) or {}).get("cors_findings", []):
        if c.get("severity") in ("critical", "high"):
            flags.append({"severity": c["severity"], "source": "cors", "title": c.get("test"),
                          "detail": c.get("note"), "host": c.get("host")})

    cloud = read_json("report/cloud_exposure.json", {}) or {}
    for b in cloud.get("buckets_found_active", []):
        if "PUBLIC" in (b.get("status") or ""):
            flags.append({"severity": "critical", "source": "cloud_exposure",
                          "title": f"Public {b.get('provider')} bucket", "detail": b.get("bucket"), "host": b.get("url")})
    for f in cloud.get("exposed_cicd_k8s_files", []):
        flags.append({"severity": "high", "source": "cloud_exposure", "title": "Exposed CI/CD/K8s config",
                      "detail": f.get("url"), "host": f.get("host")})

    sm = read_json("report/source_maps.json", {}) or {}
    for m in sm.get("maps", []):
        for s in m.get("secrets", []):
            if s.get("confidence") == "high":
                flags.append({"severity": "high", "source": "source_maps",
                              "title": f"{s.get('type')} secret in recovered source",
                              "detail": s.get("value_masked"), "host": m.get("js_url")})

    js = read_json("report/js_findings.json", {}) or {}
    for s in js.get("secrets", []):
        if s.get("confidence") == "high":
            flags.append({"severity": "high", "source": "js_secrets", "title": f"{s.get('type')} secret in JS",
                          "detail": s.get("value_masked"), "host": ", ".join(s.get("files", []))})

    for line in read_lines("nuclei/nuclei_critical.txt"):
        m = NUCLEI_LINE_RE.match(line)
        if m:
            template, protocol, severity, target = m.groups()
            flags.append({"severity": severity.lower(), "source": "nuclei", "title": template,
                          "detail": protocol, "host": target})

    for f in (read_json("report/sensitive_files.json", {}) or {}).get("findings", []):
        if f.get("status", 999) < 300:
            flags.append({"severity": "high", "source": "sensitive_files", "title": "Exposed sensitive file",
                          "detail": f.get("path"), "host": f.get("url")})

    # light dedup: same (host, title) reported twice by different sources is
    # collapsed to one entry, keeping whichever source found it first
    seen = set()
    deduped = []
    for f in flags:
        key = (f.get("host"), f.get("title"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)

    deduped.sort(key=lambda f: {"critical": 0, "high": 1}.get(f["severity"], 2))
    return deduped


def main():
    flags = collect()
    critical_count = len([f for f in flags if f["severity"] == "critical"])
    high_count = len([f for f in flags if f["severity"] == "high"])

    os.makedirs("report", exist_ok=True)
    summary = {"total_flags": len(flags), "critical_count": critical_count, "high_count": high_count, "flags": flags}
    with open("report/flags.json", "w") as f:
        json.dump(summary, f, indent=2)

    with open("report/flags.txt", "w") as f:
        f.write(f"TOTAL FLAGS: {len(flags)}  ({critical_count} critical, {high_count} high)\n")
        f.write("=" * 60 + "\n\n")
        for flag in flags:
            f.write(f"[{flag['severity'].upper()}] {flag.get('title') or '(untitled)'}\n")
            f.write(f"    source: {flag['source']}\n")
            if flag.get("host"):
                f.write(f"    host/url: {flag['host']}\n")
            if flag.get("detail"):
                f.write(f"    detail: {flag['detail']}\n")
            f.write("\n")

    print(f"  ✓ Flags collected: {len(flags)} total ({critical_count} critical, {high_count} high) -> report/flags.txt")


if __name__ == "__main__":
    main()
