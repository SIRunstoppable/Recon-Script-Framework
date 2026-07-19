#!/usr/bin/env python3
"""
scan_js_secrets.py

Scans every .js file in the current directory for:
  - hidden endpoints / relative & absolute paths
  - likely secrets (API keys, tokens, private keys, etc.)

Writes:
  ../report/js_findings.json   -> full structured results
  ../report/js_findings.txt    -> human-readable summary

Usage: run from inside the js/ folder created by recon-framework.sh
    python3 scan_js_secrets.py
"""
import os
import re
import json
import sys

# ---------- Secret patterns (name -> compiled regex) ----------
SECRET_PATTERNS = {
    "AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret-like": re.compile(r"(?i)aws(.{0,20})?(secret|access)(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Google OAuth Client": re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"),
    "Slack Webhook": re.compile(r"hooks\.slack\.com/services/[A-Za-z0-9/]+"),
    "Firebase DB": re.compile(r"[a-zA-Z0-9-]+\.firebaseio\.com"),
    "Generic API Key/Secret Assignment": re.compile(
        r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_/]{12,60}['\"]"
    ),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "Bearer Token": re.compile(r"Bearer\s+[A-Za-z0-9\-_.]{20,}"),
    "Private Key Block": re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----"),
    "Basic Auth in URL": re.compile(r"https?://[^\s\"'<>]+:[^\s\"'<>@]+@[^\s\"'<>]+"),
    "Stripe Key": re.compile(r"(sk|pk)_(live|test)_[0-9a-zA-Z]{16,}"),
    "GitHub Token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}"),
}

# ---------- Endpoint patterns ----------
ABS_URL_RE = re.compile(r"""https?://[^\s"'<>\\]+""")
REL_PATH_RE = re.compile(r"""["'](/[a-zA-Z0-9_\-./]{2,}?)["']""")

# noisy static-asset extensions we don't care about as "endpoints"
NOISE_EXT = re.compile(r"\.(png|jpe?g|gif|svg|css|woff2?|ttf|eot|ico|map)(\?.*)?$", re.I)


def truncate(secret, keep=6):
    if len(secret) <= keep * 2:
        return secret
    return f"{secret[:keep]}...{secret[-keep:]}"


def scan_file(path):
    findings = {"secrets": [], "endpoints": set()}
    try:
        with open(path, "r", errors="ignore") as f:
            content = f.read()
    except Exception:
        return findings

    for name, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(content):
            raw = m.group(0)
            findings["secrets"].append({"type": name, "value_masked": truncate(raw)})

    for m in ABS_URL_RE.finditer(content):
        url = m.group(0).rstrip("',\")")
        if not NOISE_EXT.search(url):
            findings["endpoints"].add(url)

    for m in REL_PATH_RE.finditer(content):
        path_str = m.group(1)
        if not NOISE_EXT.search(path_str) and len(path_str) > 2:
            findings["endpoints"].add(path_str)

    findings["endpoints"] = sorted(findings["endpoints"])
    return findings


def main():
    js_files = [f for f in os.listdir(".") if f.endswith(".js")]
    all_secrets = []
    all_endpoints = set()
    per_file = {}

    for fname in js_files:
        result = scan_file(fname)
        if result["secrets"] or result["endpoints"]:
            per_file[fname] = result
        for s in result["secrets"]:
            all_secrets.append({**s, "file": fname})
        all_endpoints.update(result["endpoints"])

    os.makedirs("../report", exist_ok=True)

    summary = {
        "js_files_scanned": len(js_files),
        "files_with_findings": len(per_file),
        "total_secrets_found": len(all_secrets),
        "total_unique_endpoints": len(all_endpoints),
        "secrets": all_secrets,
        "endpoints_sample": sorted(all_endpoints)[:200],
    }

    with open("../report/js_findings.json", "w") as f:
        json.dump(summary, f, indent=2)

    with open("../report/js_findings.txt", "w") as f:
        f.write(f"JS files scanned: {len(js_files)}\n")
        f.write(f"Files with findings: {len(per_file)}\n")
        f.write(f"Potential secrets found: {len(all_secrets)}\n")
        f.write(f"Unique endpoints extracted: {len(all_endpoints)}\n\n")
        if all_secrets:
            f.write("=== POTENTIAL SECRETS (masked) ===\n")
            for s in all_secrets:
                f.write(f"[{s['type']}] {s['value_masked']}  <- {s['file']}\n")
            f.write("\n")
        f.write("=== ENDPOINTS ===\n")
        for e in sorted(all_endpoints):
            f.write(e + "\n")

    print(f"  ✓ JS analysis: {len(all_secrets)} potential secrets, {len(all_endpoints)} endpoints -> ../report/js_findings.*")


if __name__ == "__main__":
    main()