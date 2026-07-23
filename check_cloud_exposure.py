#!/usr/bin/env python3
"""
check_cloud_exposure.py <domain>

Five related checks:

1. S3 bucket discovery — generates candidate bucket names from the domain
   (company-name, company-name-backup, company-name-dev, ...) and checks
   each against S3's virtual-hosted and path-style URLs. A 200 with a
   listable XML body means public + listable; 403 means the bucket exists
   but is access-controlled (still confirms the name, useful recon).

2. Azure Blob Storage discovery — same idea against
   <name>.blob.core.windows.net.

3. Passive cloud reference extraction — greps already-collected URLs and
   downloaded JS files for any S3/Azure bucket hostnames mentioned in the
   app's own code/traffic. This catches buckets that active guessing would
   never find (non-obvious names) with zero extra requests to guess.

4. GitHub repository search — queries GitHub's public, unauthenticated
   search API for repos matching the company/domain name. Flags this as a
   manual-review lead (public repos sometimes leak internal tooling,
   configs, or credentials) rather than deep-scanning file trees, to avoid
   GitHub's strict unauthenticated rate limits.

5. Exposed CI/CD & Docker/Kubernetes config files — probes common paths
   (.github/workflows/*.yml, Jenkinsfile, docker-compose.yml, k8s manifests,
   Helm values.yaml, .kube/config...) on every live host, with the same
   baseline soft-404 filtering used in check_sensitive_files.py.

Reads:  live/httpx_live.txt, urls/all_urls.txt, js/*.js
Writes: report/cloud_exposure.json
        report/cloud_exposure.txt

Usage: run from WORKDIR root
    python3 check_cloud_exposure.py <domain>

Requires: requests (pip install requests --break-system-packages)
"""
import os
import re
import sys
import json
import random
import string
import concurrent.futures

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("  ⚠ 'requests' not installed — skipping cloud exposure check.")
    print("    pip install requests --break-system-packages")
    raise SystemExit(0)

TIMEOUT = 8
MAX_WORKERS = 15

CICD_K8S_PATHS = [
    "/.github/workflows/main.yml", "/.github/workflows/ci.yml", "/.github/workflows/deploy.yml",
    "/.gitlab-ci.yml", "/.circleci/config.yml", "/Jenkinsfile", "/.travis.yml",
    "/azure-pipelines.yml", "/bitbucket-pipelines.yml",
    "/k8s/deployment.yaml", "/kubernetes/deployment.yaml", "/deployment.yaml",
    "/values.yaml", "/helm/values.yaml", "/.kube/config",
    "/docker-compose.yml", "/docker-compose.yaml", "/docker-compose.override.yml",
    "/Dockerfile", "/Dockerfile.prod", "/.dockerignore",
]

S3_REGEX = re.compile(r"([a-z0-9.\-]+?)\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com|s3\.amazonaws\.com/([a-z0-9.\-]+)", re.I)
AZURE_REGEX = re.compile(r"([a-z0-9\-]+)\.blob\.core\.windows\.net", re.I)


# ---------- bucket name generation + active checks ----------

def bucket_name_candidates(domain):
    base = domain.split(".")[0]
    suffixes = ["", "-backup", "-backups", "-dev", "-staging", "-prod", "-assets",
                "-static", "-uploads", "-media", "-files", "-data", "-logs",
                "-images", "-cdn", "-public", "-private", "-storage", "-app"]
    names = set()
    for prefix in ("", "www-"):
        for s in suffixes:
            names.add(f"{prefix}{base}{s}")
    return sorted(names)


def check_s3_bucket(name):
    for url in (f"https://{name}.s3.amazonaws.com", f"https://s3.amazonaws.com/{name}"):
        try:
            r = requests.get(url, timeout=TIMEOUT, verify=False)
        except Exception:
            continue
        if r.status_code == 200 and ("<ListBucketResult" in r.text or "<Contents>" in r.text):
            return {"provider": "AWS S3", "bucket": name, "url": url, "status": "PUBLIC - listable"}
        elif r.status_code == 403:
            return {"provider": "AWS S3", "bucket": name, "url": url, "status": "exists, access denied"}
    return None


def check_azure_blob(name):
    url = f"https://{name}.blob.core.windows.net/?comp=list"
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False)
    except Exception:
        return None
    if r.status_code == 200 and "<EnumerationResults" in r.text:
        return {"provider": "Azure Blob", "bucket": name, "url": url, "status": "PUBLIC - listable"}
    elif r.status_code == 403:
        return {"provider": "Azure Blob", "bucket": name, "url": url, "status": "exists, access denied"}
    return None


def active_bucket_scan(domain):
    candidates = bucket_name_candidates(domain)
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {}
        for n in candidates:
            futures[ex.submit(check_s3_bucket, n)] = n
            futures[ex.submit(check_azure_blob, n)] = n
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                found.append(res)
    return found


# ---------- passive extraction from already-collected data ----------

def passive_cloud_refs():
    found = set()
    sources = []
    if os.path.isfile("urls/all_urls.txt"):
        sources.append("urls/all_urls.txt")
    if os.path.isdir("js"):
        for fn in os.listdir("js"):
            if fn.endswith(".js"):
                sources.append(os.path.join("js", fn))

    for src in sources:
        try:
            with open(src, "r", errors="ignore") as f:
                content = f.read()
        except Exception:
            continue
        for m in S3_REGEX.finditer(content):
            name = (m.group(1) or m.group(2) or "").lower().strip(".")
            if name and "amazonaws" not in name:
                found.add(("AWS S3 (passive)", name))
        for m in AZURE_REGEX.finditer(content):
            found.add(("Azure Blob (passive)", m.group(1).lower()))

    return [{"provider": p, "bucket": b, "url": f"https://{b}", "status": "referenced in app code/traffic"} for p, b in found]


# ---------- GitHub repo search ----------

def search_github_repos(query):
    try:
        r = requests.get(
            "https://api.github.com/search/repositories",
            params={"q": query, "per_page": 10, "sort": "updated"},
            headers={"Accept": "application/vnd.github+json"},
            timeout=TIMEOUT,
        )
    except Exception:
        return []
    if r.status_code != 200:
        return []
    items = (r.json() or {}).get("items", [])
    return [{
        "name": item.get("full_name"),
        "url": item.get("html_url"),
        "description": item.get("description"),
        "stars": item.get("stargazers_count"),
        "updated_at": item.get("updated_at"),
    } for item in items[:10]]


# ---------- CI/CD & Docker/K8s exposed files ----------

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
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
    try:
        r = requests.get(f"{host}/__nonexistent_{rand}__", timeout=TIMEOUT, verify=False, allow_redirects=False)
        return r.status_code, len(r.content)
    except Exception:
        return None, None


def check_cicd_k8s(host):
    findings = []
    base_status, base_len = get_baseline(host)
    for path in CICD_K8S_PATHS:
        try:
            r = requests.get(host + path, timeout=TIMEOUT, verify=False, allow_redirects=False)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        if base_status is not None and r.status_code == base_status and abs(len(r.content) - (base_len or 0)) < 15:
            continue
        findings.append({"host": host, "path": path, "url": host + path, "length": len(r.content)})
    return findings


def main():
    domain = sys.argv[1] if len(sys.argv) > 1 else None
    if not domain:
        print("  ⚠ no domain passed — skipping cloud exposure check")
        return

    print("  scanning for S3/Azure buckets (active guess)...")
    active_buckets = active_bucket_scan(domain)
    passive_buckets = passive_cloud_refs()

    print("  searching GitHub for related repositories...")
    github_repos = search_github_repos(domain.split(".")[0])

    hosts = read_hosts()
    cicd_findings = []
    if hosts:
        print(f"  checking {len(hosts)} host(s) for exposed CI/CD & container configs...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            for res in ex.map(check_cicd_k8s, hosts):
                cicd_findings.extend(res)

    os.makedirs("report", exist_ok=True)
    summary = {
        "domain": domain,
        "buckets_found_active": active_buckets,
        "buckets_found_passive": passive_buckets,
        "github_repos": github_repos,
        "exposed_cicd_k8s_files": cicd_findings,
    }
    with open("report/cloud_exposure.json", "w") as f:
        json.dump(summary, f, indent=2)

    with open("report/cloud_exposure.txt", "w") as f:
        f.write(f"Domain: {domain}\n\n")
        f.write(f"=== S3/AZURE BUCKETS — active guess ({len(active_buckets)}) ===\n")
        for b in active_buckets:
            f.write(f"[{b['status']}] {b['provider']}: {b['url']}\n")
        f.write(f"\n=== S3/AZURE BUCKETS — referenced in collected app data ({len(passive_buckets)}) ===\n")
        for b in passive_buckets:
            f.write(f"{b['provider']}: {b['bucket']}\n")
        f.write(f"\n=== GITHUB REPOS matching '{domain.split('.')[0]}' ({len(github_repos)}) — manual review leads ===\n")
        for repo in github_repos:
            f.write(f"{repo['name']}  ({repo['stars']}★, updated {repo['updated_at']})\n  {repo['url']}\n  {repo['description'] or ''}\n")
        f.write(f"\n=== EXPOSED CI/CD & DOCKER/K8S CONFIGS ({len(cicd_findings)}) ===\n")
        for c in cicd_findings:
            f.write(f"{c['url']}  ({c['length']} bytes)\n")

    print(f"  ✓ Cloud exposure check: {len(active_buckets)} active + {len(passive_buckets)} passive bucket refs, "
          f"{len(github_repos)} GitHub repos, {len(cicd_findings)} exposed CI/CD/K8s files -> report/cloud_exposure.*")


if __name__ == "__main__":
    main()
