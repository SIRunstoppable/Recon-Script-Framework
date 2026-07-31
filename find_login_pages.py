#!/usr/bin/env python3
"""
find_login_pages.py

Finds login pages that are actually LIVE and working — not just guessed
paths. A candidate only counts as found if the response:
  - is reachable (status < 400), AND
  - doesn't match the host's own soft-404 baseline (same technique used in
    check_sensitive_files.py), AND
  - contains a real <input type="password"> field (high confidence) OR
    strong login-related keywords in the title/body/URL (medium confidence)

Candidate URLs come from two sources:
  1. A curated list of common login paths, probed directly per live host.
  2. Already-discovered URLs from earlier steps (content_discovery,
     sensitive_files) whose path looks login-related — these get verified
     rather than guessed, since they're already confirmed-accessible.

Reads:  live/httpx_live.txt, report/content_discovery.json, report/sensitive_files.json
Writes: report/login_pages.json   (full detail, with confidence per entry)
        report/login_pages.txt    (plain list of URLs only, one per line —
                                    the "just the login pages, by themselves" file)

Usage: run from WORKDIR root
    python3 find_login_pages.py

Requires: requests (via rate_limiter.py)
"""
import os
import re
import json
import random
import string
import concurrent.futures

try:
    from rate_limiter import get, MAX_WORKERS
except ImportError:
    print("  ⚠ rate_limiter.py not found next to this script — skipping login page discovery.")
    raise SystemExit(0)

TIMEOUT = 8

LOGIN_PATH_CANDIDATES = [
    "/", "/login", "/signin", "/sign-in", "/log-in", "/user/login",
    "/account/login", "/admin/login", "/wp-login.php", "/auth/login",
    "/users/sign_in", "/login.php", "/login.aspx", "/Account/Login",
    "/portal/login", "/cp/login", "/sso/login", "/adminlogin",
    "/login.html", "/authentication/login", "/customer/login",
]

PASSWORD_FIELD_RE = re.compile(r'<input[^>]+type=["\']password["\']', re.I)
LOGIN_KEYWORD_RE = re.compile(r'\b(log\s?in|sign\s?in|username|password)\b', re.I)


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


def read_json(path, default=None):
    if not os.path.isfile(path):
        return default
    try:
        with open(path, "r", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return default


def read_extra_candidates():
    """Already-discovered URLs whose path looks login-related — verify
    real findings instead of only guessing blind paths."""
    candidates = set()
    for src in ("report/content_discovery.json", "report/sensitive_files.json"):
        data = read_json(src, {}) or {}
        for f in data.get("findings", []):
            url = f.get("url")
            if url and re.search(r"login|signin|sign-in|auth", url, re.I):
                candidates.add(url)
    return candidates


def get_baseline(host):
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
    try:
        r = get(f"{host}/__nonexistent_{rand}__", timeout=TIMEOUT, verify=False, allow_redirects=True)
        return r.status_code, len(r.content)
    except Exception:
        return None, None


def check_url(url, baseline=None):
    try:
        r = get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
    except Exception:
        return None
    if r.status_code >= 400:
        return None
    if baseline and baseline[0] is not None and r.status_code == baseline[0] and abs(len(r.content) - (baseline[1] or 0)) < 15:
        return None  # matches this host's soft-404/block-page baseline

    body = r.text or ""
    has_password_field = bool(PASSWORD_FIELD_RE.search(body))
    has_keyword = bool(LOGIN_KEYWORD_RE.search(body[:5000])) or bool(LOGIN_KEYWORD_RE.search(r.url))
    if not (has_password_field or has_keyword):
        return None

    return {
        "url": r.url,  # final URL after any redirect
        "status": r.status_code,
        "confidence": "high" if has_password_field else "medium",
        "has_password_field": has_password_field,
    }


def scan_host(host):
    baseline = get_baseline(host)
    found = []
    for path in LOGIN_PATH_CANDIDATES:
        result = check_url(host + path, baseline)
        if result:
            found.append(result)
    return found


def main():
    hosts = read_hosts()
    extra_candidates = read_extra_candidates()

    all_results = []
    seen_urls = set()

    if hosts:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            for i, results in enumerate(ex.map(scan_host, hosts), 1):
                for r in results:
                    if r["url"] not in seen_urls:
                        seen_urls.add(r["url"])
                        all_results.append(r)
                print(f"\r  checking hosts for login pages  {i}/{len(hosts)}   ", end="", flush=True)
    print("")

    for url in extra_candidates:
        if url in seen_urls:
            continue
        result = check_url(url)
        if result and result["url"] not in seen_urls:
            seen_urls.add(result["url"])
            all_results.append(result)

    all_results.sort(key=lambda r: r["confidence"] != "high")  # high-confidence first

    os.makedirs("report", exist_ok=True)
    high_conf = [r for r in all_results if r["confidence"] == "high"]

    summary = {
        "hosts_scanned": len(hosts),
        "total_login_pages_found": len(all_results),
        "high_confidence_count": len(high_conf),
        "login_pages": all_results,
    }
    with open("report/login_pages.json", "w") as f:
        json.dump(summary, f, indent=2)

    # The dedicated "just the login pages, by themselves" file — plain URLs,
    # one per line, high-confidence (confirmed password field) first.
    with open("report/login_pages.txt", "w") as f:
        for r in all_results:
            f.write(r["url"] + "\n")

    print(f"  ✓ Login page discovery: {len(all_results)} working login page(s) found "
          f"({len(high_conf)} with a confirmed password field) -> report/login_pages.txt")


if __name__ == "__main__":
    main()
