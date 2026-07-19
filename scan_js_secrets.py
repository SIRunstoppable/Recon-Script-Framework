#!/usr/bin/env python3
"""
scan_js_secrets.py

Scans every .js file in the current directory for:
  - hidden endpoints / relative & absolute paths
  - likely secrets (API keys, tokens, private keys, etc.)

Each secret is scored with a confidence (high/low) using two signals:
  1. Shannon entropy of the extracted value — real keys are close to random,
     placeholder words like "test123" or repeated chars like "aaaaaaaa" are not.
  2. A denylist of common placeholder/example substrings (e.g. "example",
     "changeme", "your_api_key_here", "xxxxxxxx").
Structurally-strict patterns (AWS AKIA prefix, Google AIza prefix, private key
blocks, Stripe/GitHub token prefixes, ...) start as high confidence but are
still demoted if they hit the denylist (this catches things like AWS's own
publicly documented example key "AKIAIOSFODNN7EXAMPLE").

Writes:
  ../report/js_findings.json   -> full structured results (all secrets, with confidence)
  ../report/js_findings.txt    -> human-readable summary, high-confidence first

Usage: run from inside the js/ folder created by recon-framework.sh
    python3 scan_js_secrets.py
"""
import os
import re
import json
import math
from collections import Counter

# ---------- Secret patterns (name -> (regex, structurally_strict)) ----------
# structurally_strict=True means the pattern itself (prefix/format) is specific
# enough that we start at high confidence rather than relying purely on entropy.
SECRET_PATTERNS = {
    "AWS Access Key ID": (re.compile(r"AKIA[0-9A-Z]{16}"), True),
    "AWS Secret-like": (re.compile(r"(?i)aws(.{0,20})?(secret|access)(.{0,20})?['\"]([0-9a-zA-Z/+]{40})['\"]"), False),
    "Google API Key": (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), True),
    "Google OAuth Client": (re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"), True),
    "Slack Token": (re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"), True),
    "Slack Webhook": (re.compile(r"hooks\.slack\.com/services/[A-Za-z0-9/]+"), True),
    "Firebase DB": (re.compile(r"[a-zA-Z0-9-]+\.firebaseio\.com"), True),
    "Generic API Key/Secret Assignment": (
        re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z\-_/]{12,60})['\"]"),
        False,
    ),
    "JWT": (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), False),
    "Bearer Token": (re.compile(r"Bearer\s+([A-Za-z0-9\-_.]{20,})"), False),
    "Private Key Block": (re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----"), True),
    "Basic Auth in URL": (re.compile(r"https?://[^\s\"'<>]+:([^\s\"'<>@]+)@[^\s\"'<>]+"), False),
    "Stripe Key": (re.compile(r"(sk|pk)_(live|test)_[0-9a-zA-Z]{16,}"), True),
    "GitHub Token": (re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}"), True),
}

# ---------- Endpoint patterns ----------
ABS_URL_RE = re.compile(r"""https?://[^\s"'<>\\]+""")
REL_PATH_RE = re.compile(r"""["'](/[a-zA-Z0-9_\-./]{2,}?)["']""")
NOISE_EXT = re.compile(r"\.(png|jpe?g|gif|svg|css|woff2?|ttf|eot|ico|map)(\?.*)?$", re.I)

# ---------- False-positive reduction ----------
PLACEHOLDER_SUBSTRINGS = [
    "example", "changeme", "change_me", "your_api_key", "your-api-key",
    "yourkey", "insert_key", "insert-key", "replace_me", "replace-me",
    "placeholder", "dummy", "sample", "fake", "todo", "xxxxxxxx",
    "api_key_here", "apikeyhere", "secret_here", "token_here",
    "test_key", "testkey", "0000000000", "1111111111", "1234567890",
    "abcdefgh", "null", "undefined", "n/a", "notreal", "redacted",
]

ENTROPY_THRESHOLD = 3.0  # bits/char — below this, treat as low-confidence


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def looks_like_placeholder(value):
    low = value.lower()
    if any(sub in low for sub in PLACEHOLDER_SUBSTRINGS):
        return True
    # too few distinct characters (e.g. "aaaaaaaaaaaa", "01010101")
    if len(set(low)) <= 3 and len(low) >= 8:
        return True
    return False


def truncate(secret, keep=6):
    if len(secret) <= keep * 2:
        return secret
    return f"{secret[:keep]}...{secret[-keep:]}"


def extract_value(match, pattern_has_group):
    """Pull the actual secret token out of the match, not the surrounding
    key-name text (e.g. skip 'api_key: ' and just look at the value)."""
    if pattern_has_group:
        groups = [g for g in match.groups() if g]
        if groups:
            return groups[-1]
    return match.group(0)


def classify(value, structurally_strict):
    placeholder = looks_like_placeholder(value)
    entropy = shannon_entropy(value)

    if placeholder:
        return "low", f"matches known placeholder pattern (entropy={entropy:.1f})"

    if structurally_strict:
        return "high", f"matches strict provider format (entropy={entropy:.1f})"

    if entropy >= ENTROPY_THRESHOLD:
        return "high", f"high entropy, looks random (entropy={entropy:.1f})"

    return "low", f"low entropy, likely not a real secret (entropy={entropy:.1f})"


def scan_file(path):
    findings = {"secrets": [], "endpoints": set()}
    try:
        with open(path, "r", errors="ignore") as f:
            content = f.read()
    except Exception:
        return findings

    for name, (pattern, strict) in SECRET_PATTERNS.items():
        has_group = pattern.groups > 0
        for m in pattern.finditer(content):
            raw = m.group(0)
            value = extract_value(m, has_group)
            confidence, reason = classify(value, strict)
            findings["secrets"].append({
                "type": name,
                "value_masked": truncate(value),
                "confidence": confidence,
                "reason": reason,
            })

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


def dedup_secrets(all_secrets):
    """Merge identical (type, value_masked) hits across files into one entry
    with a list of files, so the same key reused across bundles isn't spammed."""
    merged = {}
    for s in all_secrets:
        key = (s["type"], s["value_masked"])
        if key not in merged:
            merged[key] = {**s, "files": [s["file"]]}
        else:
            if s["file"] not in merged[key]["files"]:
                merged[key]["files"].append(s["file"])
    return list(merged.values())


def main():
    js_files = [f for f in os.listdir(".") if f.endswith(".js")]
    raw_secrets = []
    all_endpoints = set()
    per_file = {}

    for fname in js_files:
        result = scan_file(fname)
        if result["secrets"] or result["endpoints"]:
            per_file[fname] = result
        for s in result["secrets"]:
            raw_secrets.append({**s, "file": fname})
        all_endpoints.update(result["endpoints"])

    deduped = dedup_secrets(raw_secrets)
    high_conf = [s for s in deduped if s["confidence"] == "high"]
    low_conf = [s for s in deduped if s["confidence"] == "low"]

    os.makedirs("../report", exist_ok=True)

    summary = {
        "js_files_scanned": len(js_files),
        "files_with_findings": len(per_file),
        "total_secrets_found": len(deduped),
        "high_confidence_secrets": len(high_conf),
        "low_confidence_secrets": len(low_conf),
        "total_unique_endpoints": len(all_endpoints),
        "secrets": deduped,
        "endpoints_sample": sorted(all_endpoints)[:200],
    }

    with open("../report/js_findings.json", "w") as f:
        json.dump(summary, f, indent=2)

    with open("../report/js_findings.txt", "w") as f:
        f.write(f"JS files scanned: {len(js_files)}\n")
        f.write(f"Files with findings: {len(per_file)}\n")
        f.write(f"Potential secrets found: {len(deduped)} ({len(high_conf)} high-confidence, {len(low_conf)} low-confidence/likely noise)\n")
        f.write(f"Unique endpoints extracted: {len(all_endpoints)}\n\n")

        if high_conf:
            f.write("=== HIGH-CONFIDENCE SECRETS (verify these first) ===\n")
            for s in high_conf:
                files = ", ".join(s["files"])
                f.write(f"[{s['type']}] {s['value_masked']}  <- {files}\n    reason: {s['reason']}\n")
            f.write("\n")

        if low_conf:
            f.write("=== LOW-CONFIDENCE / LIKELY NOISE (review only if time allows) ===\n")
            for s in low_conf:
                files = ", ".join(s["files"])
                f.write(f"[{s['type']}] {s['value_masked']}  <- {files}\n    reason: {s['reason']}\n")
            f.write("\n")

        f.write("=== ENDPOINTS ===\n")
        for e in sorted(all_endpoints):
            f.write(e + "\n")

    print(f"  ✓ JS analysis: {len(high_conf)} high-confidence + {len(low_conf)} low-confidence secrets, "
          f"{len(all_endpoints)} endpoints -> ../report/js_findings.*")


if __name__ == "__main__":
    main()