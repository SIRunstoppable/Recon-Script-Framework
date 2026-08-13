#!/usr/bin/env python3
"""
find_juicy_files.py

"Juicy files" — bug-bounty slang for exposed backup/database/config files
that commonly leak credentials, schemas, or source code: .sql, .pak, .zip,
.env, .db (plus a few natural variants of each).

Two sources, merged and deduped:

  1. PASSIVE — re-scans everything already collected by earlier steps
     (content_discovery.json, sensitive_files.json, urls/all_urls.txt,
     source_maps.json endpoints) for any URL ending in one of the target
     extensions. Zero extra requests to the target.

  2. ACTIVE — probes a curated list of common backup/dump/config filenames
     per live host (backup.sql, dump.sql, db.zip, .env.bak, database.db...),
     using the same baseline soft-404 filtering as check_sensitive_files.py
     so custom "not found" pages don't produce false positives.

Reads:  live/httpx_live.txt, urls/all_urls.txt, report/content_discovery.json,
        report/sensitive_files.json, report/source_maps.json
Writes: report/juicy_files.json    (full detail incl. source: passive/active)
        report/juicy_files.txt     (plain URL list, one per line — the
                                     dedicated "just these files" output)

Usage: run from WORKDIR root
    python3 find_juicy_files.py
"""
import os
import re
import json
import random
import string
import concurrent.futures
from urllib.parse import urlparse

try:
    from rate_limiter import get, MAX_WORKERS
except ImportError:
    get = None
    MAX_WORKERS = 15

TIMEOUT = 8

EXTENSIONS = [".sql", ".pak", ".zip", ".env", ".db"]
EXTENSION_RE = re.compile(r"\.(sql(\.gz)?|pak|zip|env(\.bak|\.local|\.old)?|db|sqlite3?)$", re.I)

ACTIVE_CANDIDATES = [
    "/backup.sql", "/dump.sql", "/database.sql", "/db.sql", "/db_backup.sql",
    "/site-backup.sql", "/backup.zip", "/site.zip", "/www.zip", "/backup.tar.zip",
    "/data.pak", "/game.pak", "/assets.pak", "/resources.pak",
    "/.env", "/.env.bak", "/.env.local", "/.env.old", "/.env.production",
    "/database.db", "/db.sqlite", "/db.sqlite3", "/app.db", "/data.db",
]


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


def matches_extension(url):
    path = urlparse(url).path if "://" in url else url
    return bool(EXTENSION_RE.search(path))


def passive_scan():
    found = {}  # url -> source label

    for url in read_lines("urls/all_urls.txt"):
        if matches_extension(url):
            found.setdefault(url, "passive:collected_urls")

    content_disc = read_json("report/content_discovery.json", {}) or {}
    for f in content_disc.get("findings", []):
        url = f.get("url")
        if url and matches_extension(url):
            found[url] = "passive:content_discovery"

    sensitive = read_json("report/sensitive_files.json", {}) or {}
    for f in sensitive.get("findings", []):
        url = f.get("url")
        if url and matches_extension(url):
            found[url] = "passive:sensitive_files"

    source_maps = read_json("report/source_maps.json", {}) or {}
    for m in source_maps.get("maps", []):
        for ep in m.get("endpoints", []):
            if matches_extension(ep):
                found.setdefault(ep, "passive:source_maps")

    return found


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


def get_baseline(host):
    if not get:
        return None, None
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
    try:
        r = get(f"{host}/__nonexistent_{rand}__", timeout=TIMEOUT, verify=False, allow_redirects=False)
        return r.status_code, r.content
    except Exception:
        return None, None


def active_probe_host(host):
    if not get:
        return []
    found = []
    base_status, base_content = get_baseline(host)
    for path in ACTIVE_CANDIDATES:
        try:
            r = get(host + path, timeout=TIMEOUT, verify=False, allow_redirects=False)
        except Exception:
            continue
        if r.status_code >= 400:
            continue
        # Compare actual content, not just length — two different real files
        # can coincidentally be close in size to the soft-404 page, which a
        # length-only threshold would wrongly filter out as a false negative.
        if base_status is not None and r.status_code == base_status and r.content == base_content:
            continue  # byte-identical to the soft-404 page — not a real file
        found.append({"url": host + path, "status": r.status_code, "length": len(r.content)})
    return found


def main():
    passive_results = passive_scan()

    hosts = read_hosts()
    active_results = []
    if hosts and get:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            for i, findings in enumerate(ex.map(active_probe_host, hosts), 1):
                active_results.extend(findings)
                print(f"\r  probing for juicy files (sql/pak/zip/env/db)  {i}/{len(hosts)}   ", end="", flush=True)
        print("")

    all_files = {}
    for url, source in passive_results.items():
        all_files[url] = {"url": url, "source": source, "status": None, "length": None}
    for f in active_results:
        if f["url"] in all_files:
            all_files[f["url"]]["status"] = f["status"]
            all_files[f["url"]]["length"] = f["length"]
            all_files[f["url"]]["source"] += "+active:probe"
        else:
            all_files[f["url"]] = {"url": f["url"], "source": "active:probe", "status": f["status"], "length": f["length"]}

    results = sorted(all_files.values(), key=lambda x: x["url"])

    by_ext = {}
    for r in results:
        ext_match = EXTENSION_RE.search(urlparse(r["url"]).path if "://" in r["url"] else r["url"])
        ext = ext_match.group(0).lower() if ext_match else "?"
        by_ext.setdefault(ext, []).append(r["url"])

    os.makedirs("report", exist_ok=True)
    summary = {
        "total_found": len(results),
        "by_extension_count": {k: len(v) for k, v in by_ext.items()},
        "files": results,
    }
    with open("report/juicy_files.json", "w") as f:
        json.dump(summary, f, indent=2)

    # The dedicated "just these files" plain output — one URL per line.
    with open("report/juicy_files.txt", "w") as f:
        for r in results:
            f.write(r["url"] + "\n")

    print(f"  ✓ Juicy file discovery: {len(results)} file(s) found "
          f"({', '.join(f'{k}:{len(v)}' for k, v in by_ext.items())}) -> report/juicy_files.txt")


if __name__ == "__main__":
    main()
