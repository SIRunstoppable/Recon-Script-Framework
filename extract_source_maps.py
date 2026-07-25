#!/usr/bin/env python3
"""
extract_source_maps.py

Many production builds accidentally ship .js.map files alongside their
minified JS. A source map is a JSON file that maps minified code back to
the original, unminified source — including original file names, and often
the FULL original source text in a "sourcesContent" field. If that field is
present, this script reconstructs the original source tree on disk and runs
it through the same secret/endpoint detection engine used on the minified
JS (scan_js_secrets.py) — unminified code is far easier to read and often
reveals things (internal API calls, comments, debug code) that never show
up in the minified bundle.

Discovery strategy per JS URL:
  1. Look for a `//# sourceMappingURL=...` comment in the already-downloaded
     local copy of the JS file (from the js/ harvesting step) and resolve
     it relative to the JS URL.
  2. Fallback: try `<js_url>.map` directly — the overwhelmingly common
     convention when build tools emit maps without rewriting the comment.

Reads:  js/js_urls.txt, js/*.js (already downloaded)
Writes: report/source_maps.json
        report/source_maps.txt
        js/recovered_sources/<...>/           (reconstructed original source files)

Usage: run from WORKDIR root
    python3 extract_source_maps.py

Requires: requests (pip install requests --break-system-packages)
"""
import os
import re
import json
import concurrent.futures
from urllib.parse import urljoin

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("  ⚠ 'requests' not installed — skipping source map check.")
    print("    pip install requests --break-system-packages")
    raise SystemExit(0)

# Reuse the same secret/endpoint patterns + entropy/denylist confidence
# scoring already validated in scan_js_secrets.py, instead of duplicating it.
try:
    import scan_js_secrets as sjs
except ImportError:
    sjs = None

from rate_limiter import get, MAX_WORKERS

TIMEOUT = 10
MAX_SOURCES_PER_MAP = 200

SOURCEMAP_COMMENT_RE = re.compile(r"//#\s*sourceMappingURL=(\S+)|/\*#\s*sourceMappingURL=(\S+?)\s*\*/")


def read_js_urls(path="js/js_urls.txt"):
    if not os.path.isfile(path):
        return []
    with open(path, "r", errors="ignore") as f:
        return [l.strip() for l in f if l.strip()]


def local_js_path_for(url):
    fname = re.sub(r"[^a-zA-Z0-9]", "_", url) + ".js"
    p = os.path.join("js", fname)
    return p if os.path.isfile(p) else None


def find_sourcemap_url(js_url):
    local_path = local_js_path_for(js_url)
    if local_path:
        try:
            with open(local_path, "r", errors="ignore") as f:
                content = f.read()
            m = SOURCEMAP_COMMENT_RE.search(content[-2000:])  # comment is almost always at the very end
            if m:
                candidate = m.group(1) or m.group(2)
                return urljoin(js_url, candidate)
        except Exception:
            pass
    return js_url + ".map"  # common convention fallback


def fetch_map(map_url):
    try:
        r = get(map_url, timeout=TIMEOUT, verify=False)
    except Exception:
        return None
    if r.status_code != 200:
        return None
    try:
        data = r.json()
    except Exception:
        return None
    if not isinstance(data, dict) or "sources" not in data:
        return None
    return data


def safe_name(s, maxlen=80):
    s = re.sub(r"[^a-zA-Z0-9._-]", "_", s)
    return s[:maxlen] or "unnamed"


def scan_content_for_secrets(content, source_path, map_url):
    """Runs scan_js_secrets' pattern set against recovered plaintext source."""
    secrets, endpoints = [], set()
    if not sjs:
        return secrets, endpoints
    for name, (pattern, strict) in sjs.SECRET_PATTERNS.items():
        has_group = pattern.groups > 0
        for m in pattern.finditer(content):
            value = sjs.extract_value(m, has_group)
            confidence, reason = sjs.classify(value, strict)
            secrets.append({
                "type": name, "value_masked": sjs.truncate(value),
                "confidence": confidence, "reason": reason,
                "source_file": source_path, "from_map": map_url,
            })
    for m in sjs.ABS_URL_RE.finditer(content):
        url_ = m.group(0).rstrip("',\")")
        if not sjs.NOISE_EXT.search(url_):
            endpoints.add(url_)
    for m in sjs.REL_PATH_RE.finditer(content):
        p_ = m.group(1)
        if not sjs.NOISE_EXT.search(p_) and len(p_) > 2:
            endpoints.add(p_)
    return secrets, endpoints


def process_js_url(js_url):
    map_url = find_sourcemap_url(js_url)
    data = fetch_map(map_url)
    if not data:
        return None

    sources = data.get("sources", [])[:MAX_SOURCES_PER_MAP]
    contents = data.get("sourcesContent") or []
    recovered_dir = os.path.join("js", "recovered_sources", safe_name(js_url, 60))

    secrets, endpoints, saved_files = [], set(), 0

    for i, src_path in enumerate(sources):
        content = contents[i] if i < len(contents) else None
        if not content:
            continue
        saved_files += 1
        os.makedirs(recovered_dir, exist_ok=True)
        out_path = os.path.join(recovered_dir, safe_name(src_path or f"source_{i}.js"))
        try:
            with open(out_path, "w", errors="ignore") as f:
                f.write(content)
        except Exception:
            pass
        s, e = scan_content_for_secrets(content, src_path, map_url)
        secrets.extend(s)
        endpoints.update(e)

    return {
        "js_url": js_url,
        "map_url": map_url,
        "source_count": len(sources),
        "sources_recovered": saved_files,
        "source_paths_sample": sources[:50],
        "secrets": secrets,
        "endpoints": sorted(endpoints),
    }


def main():
    js_urls = read_js_urls()
    results = []

    if js_urls:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            for i, res in enumerate(ex.map(process_js_url, js_urls), 1):
                if res:
                    results.append(res)
                print(f"\r  checking for exposed source maps  {i}/{len(js_urls)}   ", end="", flush=True)
    print("")

    os.makedirs("report", exist_ok=True)

    all_secrets, all_endpoints = [], set()
    for r in results:
        all_secrets.extend(r["secrets"])
        all_endpoints.update(r["endpoints"])
    high_conf = [s for s in all_secrets if s["confidence"] == "high"]
    total_recovered = sum(r["sources_recovered"] for r in results)

    summary = {
        "js_urls_checked": len(js_urls),
        "maps_found": len(results),
        "total_recovered_files": total_recovered,
        "high_confidence_secrets": len(high_conf),
        "unique_endpoints_from_maps": len(all_endpoints),
        "maps": results,
    }
    with open("report/source_maps.json", "w") as f:
        json.dump(summary, f, indent=2)

    with open("report/source_maps.txt", "w") as f:
        f.write(f"JS URLs checked: {len(js_urls)}\n")
        f.write(f"Exposed source maps found: {len(results)}\n")
        f.write(f"Original source files recovered: {total_recovered}\n")
        f.write(f"High-confidence secrets found inside recovered source: {len(high_conf)}\n")
        f.write(f"Unique endpoints found inside recovered source: {len(all_endpoints)}\n\n")
        for r in results:
            f.write(f"[{r['js_url']}]\n  map: {r['map_url']}\n  sources: {r['source_count']} (recovered {r['sources_recovered']})\n")
            for p in r["source_paths_sample"][:20]:
                f.write(f"    {p}\n")
            f.write("\n")

    print(f"  ✓ Source map check: {len(results)} exposed maps, {total_recovered} source files recovered, "
          f"{len(high_conf)} high-confidence secrets -> report/source_maps.*")


if __name__ == "__main__":
    main()
