#!/usr/bin/env python3
"""
flag_interesting_params.py

Passive analysis only — no requests are sent to the target. Reads the
already-collected params/urls_with_params.txt and flags parameters whose
NAME (and sometimes VALUE) commonly indicates a vulnerability class worth
manual testing:

  - Open Redirect  : redirect=, next=, return=, dest=, url=, ...
  - SSRF           : url=, uri=, proxy=, callback=, webhook=, src=, host=, ...
  - IDOR           : id=, user_id=, order_id=, invoice_id=, ... (esp. if numeric)

Each hit gets a "signal" of strong or weak:
  - strong = the param name matches AND the value looks like a URL/IP (for
    open-redirect/SSRF) or a plain numeric ID (for IDOR) — worth testing first.
  - weak   = only the param name matched — still worth a look, lower priority.

This does NOT confirm a vulnerability. It's a triage aid: it tells you where
to spend your manual testing time first instead of reading thousands of URLs
by hand.

Reads:  params/urls_with_params.txt
Writes: report/interesting_params.json
        report/interesting_params.txt

Usage: run from WORKDIR root
    python3 flag_interesting_params.py
"""
import os
import re
import json
from urllib.parse import urlparse, parse_qsl

OPEN_REDIRECT_PARAMS = {
    "redirect", "redirect_uri", "redirect_url", "redirecturl", "return",
    "return_url", "returnurl", "returnto", "next", "continue", "dest",
    "destination", "target", "url", "link", "out", "forward", "goto",
    "checkout_url", "callback_url", "success_url", "redir", "r",
}

SSRF_PARAMS = {
    "url", "uri", "path", "dest", "destination", "redirect", "proxy",
    "fetch", "callback", "webhook", "src", "source", "host", "domain",
    "ip", "site", "feed", "load", "import", "target", "endpoint",
    "server", "resource",
}

IDOR_PARAMS = {
    "id", "uid", "user_id", "userid", "account_id", "account", "profile_id",
    "order_id", "orderid", "invoice_id", "doc_id", "document_id", "file_id",
    "ref", "reference", "key", "record_id", "cust_id", "customer_id",
    "member_id", "item_id", "product_id", "ticket_id",
}

IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def looks_like_url_or_host(value):
    if not value:
        return False
    v = value.strip()
    if v.startswith(("http://", "https://", "//")):
        return True
    if "%2f%2f" in v.lower():  # encoded //
        return True
    if IP_RE.match(v):
        return True
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$", v):  # bare domain-looking value
        return True
    return False


def is_numeric_id(value):
    return bool(value) and value.strip().isdigit()


def classify_param(name, value):
    hits = []
    lname = name.lower()

    if lname in OPEN_REDIRECT_PARAMS:
        strong = looks_like_url_or_host(value)
        hits.append(("Open Redirect", "strong" if strong else "weak"))

    if lname in SSRF_PARAMS:
        strong = looks_like_url_or_host(value)
        hits.append(("SSRF", "strong" if strong else "weak"))

    if lname in IDOR_PARAMS:
        strong = is_numeric_id(value)
        hits.append(("IDOR", "strong" if strong else "weak"))

    return hits


def main():
    src = "params/urls_with_params.txt"
    if not os.path.isfile(src):
        print(f"  ⚠ {src} not found — skipping param flagging")
        return

    with open(src, "r", errors="ignore") as f:
        urls = [l.strip() for l in f if l.strip()]

    # findings[category] = { (param_name, signal): [example urls...] }
    findings = {"Open Redirect": {}, "SSRF": {}, "IDOR": {}}

    for url in urls:
        try:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
        except Exception:
            continue
        for name, value in params:
            for category, signal in classify_param(name, value):
                key = (name, signal)
                bucket = findings[category].setdefault(key, [])
                if len(bucket) < 5 and url not in bucket:
                    bucket.append(url)

    os.makedirs("report", exist_ok=True)

    def serialize(cat_dict):
        out = []
        for (name, signal), examples in sorted(cat_dict.items(), key=lambda x: (x[0][1] != "strong", x[0][0])):
            out.append({"param": name, "signal": signal, "example_urls": examples, "count": len(examples)})
        return out

    summary = {
        "urls_analyzed": len(urls),
        "open_redirect": serialize(findings["Open Redirect"]),
        "ssrf": serialize(findings["SSRF"]),
        "idor": serialize(findings["IDOR"]),
    }

    with open("report/interesting_params.json", "w") as f:
        json.dump(summary, f, indent=2)

    def total(cat_list):
        return sum(x["count"] for x in cat_list)

    with open("report/interesting_params.txt", "w") as f:
        f.write(f"URLs analyzed: {len(urls)}\n")
        f.write("(Passive parameter-name/value triage — not confirmed vulnerabilities, manual testing required)\n\n")
        for label, cat_list in [
            ("OPEN REDIRECT", summary["open_redirect"]),
            ("SSRF", summary["ssrf"]),
            ("IDOR", summary["idor"]),
        ]:
            f.write(f"=== {label} candidates ({total(cat_list)} param/signal combos) ===\n")
            if not cat_list:
                f.write("  none found\n\n")
                continue
            for entry in cat_list:
                f.write(f"[{entry['signal'].upper()}] param='{entry['param']}'\n")
                for ex in entry["example_urls"]:
                    f.write(f"    {ex}\n")
            f.write("\n")

    total_strong = sum(
        len([e for e in summary[c] if e["signal"] == "strong"])
        for c in ("open_redirect", "ssrf", "idor")
    )
    total_weak = sum(
        len([e for e in summary[c] if e["signal"] == "weak"])
        for c in ("open_redirect", "ssrf", "idor")
    )
    print(f"  ✓ Param flagging: {total_strong} strong-signal + {total_weak} weak-signal candidates -> report/interesting_params.*")


if __name__ == "__main__":
    main()
