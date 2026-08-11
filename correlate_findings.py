#!/usr/bin/env python3
"""
correlate_findings.py

Every scanning step reports its own findings independently. This script
runs AFTER all of them and cross-references findings BY HOST to catch
compound-risk patterns — e.g. "WordPress + a matched CVE template" or
"an admin panel was found AND its IP restriction can be bypassed" — that
are much more urgent than any single finding alone, and that only a human
reading every report file side-by-side would otherwise notice.

This is deterministic (plain Python rules, not an LLM guess) so it's
consistent across runs and cheap to re-check by hand. generate_ai_report.py
reads its output and is told to treat these as pre-verified, high-confidence
findings rather than re-deriving the same conclusions itself.

Reads: report/*.json, wordpress/nuclei_wordpress.txt, nuclei/nuclei_critical.txt,
       nuclei/nuclei_exposures.txt, js/js_urls.txt
Writes: report/correlations.json
        report/correlations.txt

Usage: run from WORKDIR root, after all other steps
    python3 correlate_findings.py
"""
import os
import re
import json
from collections import defaultdict
from urllib.parse import urlparse

NUCLEI_LINE_RE = re.compile(r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)")

# Rough per-category "weight" for the generic cumulative-risk score.
# Named rules below cover the clearest specific patterns explicitly;
# this score catches "death by a thousand small cuts" cases that don't
# match any single named rule.
WEIGHTS = {
    "sensitive_file": 3,
    "content_discovery_restricted": 1,
    "ip_bypass": 5,
    "cors_critical": 4,
    "cors_other": 2,
    "misconfig": 1,
    "wordpress": 1,
    "nuclei_critical": 5,
    "nuclei_exposure": 2,
    "js_secret_high": 3,
    "cicd_k8s_exposed": 3,
    "graphql_introspection": 2,
    "login_page": 1,
}


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


def normalize_host(url_or_host):
    if not url_or_host:
        return None
    if "://" not in url_or_host:
        url_or_host = "http://" + url_or_host
    parsed = urlparse(url_or_host)
    if not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def parse_nuclei_file(path):
    """Nuclei's default text output: [template-id] [protocol] [severity] target"""
    results = []
    for line in read_lines(path):
        m = NUCLEI_LINE_RE.match(line)
        if not m:
            continue
        template, protocol, severity, target = m.groups()
        results.append({"template": template, "severity": severity, "host": normalize_host(target)})
    return results


def build_js_filename_to_host_map():
    """scan_js_secrets.py stores the sanitized local filename, not the
    original URL — reproduce the exact same sanitization (from step_js in
    recon-framework.sh: sed 's/[^a-zA-Z0-9]/_/g') to map back to a host."""
    mapping = {}
    for url in read_lines("js/js_urls.txt"):
        fname = re.sub(r"[^a-zA-Z0-9]", "_", url) + ".js"
        mapping[fname] = normalize_host(url)
    return mapping


def build_host_data():
    """Aggregates every step's findings into host_data[host] = {...}"""
    host_data = defaultdict(lambda: {
        "sensitive_files": [], "content_discovery": [], "ip_bypass": [],
        "cors": [], "misconfig": [], "wordpress": None, "nuclei_critical": [],
        "nuclei_exposures": [], "nuclei_wordpress": [], "js_secrets": [],
        "cicd_k8s": [], "graphql": [], "openapi": [], "cloud_buckets": [],
        "login_pages": [], "sqli": [], "cmdi": [],
    })

    for f in (read_json("report/sensitive_files.json", {}) or {}).get("findings", []):
        h = normalize_host(f.get("host") or f.get("url"))
        if h:
            host_data[h]["sensitive_files"].append(f)

    for f in (read_json("report/content_discovery.json", {}) or {}).get("findings", []):
        h = normalize_host(f.get("url"))
        if h:
            host_data[h]["content_discovery"].append(f)

    for f in (read_json("report/ip_bypass.json", {}) or {}).get("findings", []):
        h = normalize_host(f.get("url"))
        if h:
            host_data[h]["ip_bypass"].append(f)

    cors_data = read_json("report/cors_headers.json", {}) or {}
    for f in cors_data.get("cors_findings", []):
        h = normalize_host(f.get("host"))
        if h:
            host_data[h]["cors"].append(f)

    for f in (read_json("report/misconfig.json", {}) or {}).get("findings", []):
        h = normalize_host(f.get("host"))
        if h:
            host_data[h]["misconfig"].append(f)

    for site in (read_json("report/wordpress.json", {}) or {}).get("sites", []):
        h = normalize_host(site.get("host"))
        if h:
            host_data[h]["wordpress"] = site

    for f in parse_nuclei_file("nuclei/nuclei_critical.txt"):
        if f["host"]:
            host_data[f["host"]]["nuclei_critical"].append(f)
    for f in parse_nuclei_file("nuclei/nuclei_exposures.txt"):
        if f["host"]:
            host_data[f["host"]]["nuclei_exposures"].append(f)
    for f in parse_nuclei_file("wordpress/nuclei_wordpress.txt"):
        if f["host"]:
            host_data[f["host"]]["nuclei_wordpress"].append(f)

    js_map = build_js_filename_to_host_map()
    js_findings = read_json("report/js_findings.json", {}) or {}
    for s in js_findings.get("secrets", []):
        if s.get("confidence") != "high":
            continue
        for fname in s.get("files", []):
            h = js_map.get(fname)
            if h:
                host_data[h]["js_secrets"].append(s)

    cloud = read_json("report/cloud_exposure.json", {}) or {}
    for f in cloud.get("exposed_cicd_k8s_files", []):
        h = normalize_host(f.get("host") or f.get("url"))
        if h:
            host_data[h]["cicd_k8s"].append(f)
    for b in cloud.get("buckets_found_active", []) + cloud.get("buckets_found_passive", []):
        host_data["__cloud__"]["cloud_buckets"].append(b)  # not host-scoped, tracked globally

    api_data = read_json("report/api_endpoints.json", {}) or {}
    for g in api_data.get("graphql_endpoints", []):
        h = normalize_host(g.get("host"))
        if h:
            host_data[h]["graphql"].append(g)
    for s in api_data.get("openapi_specs", []):
        h = normalize_host(s.get("host"))
        if h:
            host_data[h]["openapi"].append(s)

    for lp in (read_json("report/login_pages.json", {}) or {}).get("login_pages", []):
        h = normalize_host(lp.get("url"))
        if h:
            host_data[h]["login_pages"].append(lp)

    for s in (read_json("report/sqli_findings.json", {}) or {}).get("findings", []):
        h = normalize_host(s.get("url"))
        if h:
            host_data[h]["sqli"].append(s)

    for c in (read_json("report/cmdi_findings.json", {}) or {}).get("findings", []):
        h = normalize_host(c.get("url"))
        if h:
            host_data[h]["cmdi"].append(c)

    return host_data


# ---------- Named correlation rules ----------
# Each rule takes (host, data) and returns a finding dict or None.

def rule_wordpress_plus_cve(host, d):
    if d["wordpress"] and d["nuclei_wordpress"]:
        templates = [f["template"] for f in d["nuclei_wordpress"]]
        return {
            "name": "WordPress with a matched CVE template",
            "severity": "critical",
            "host": host,
            "explanation": f"Confirmed WordPress (version {d['wordpress'].get('version') or 'unknown'}) AND nuclei matched "
                            f"{len(templates)} WordPress-specific template(s) against it: {', '.join(templates[:5])}. "
                            "This is a specific, actionable vulnerability, not just a version disclosure.",
        }
    return None


def rule_admin_panel_plus_ip_bypass(host, d):
    admin_paths = [c for c in d["content_discovery"] if any(
        kw in (c.get("url") or "").lower() for kw in ("admin", "manage", "console", "dashboard", "internal")
    )]
    if admin_paths and d["ip_bypass"]:
        return {
            "name": "Admin-looking panel found AND its IP restriction is bypassable",
            "severity": "critical",
            "host": host,
            "explanation": f"Content discovery found {len(admin_paths)} admin-looking path(s) on this host, and "
                            f"the IP-restriction bypass check confirmed {len(d['ip_bypass'])} path(s) here can be "
                            "accessed by spoofing an IP header. Combined, this is a near-complete access path to a "
                            "restricted admin interface, not two separate low-priority findings.",
        }
    return None


def rule_cors_plus_secrets(host, d):
    critical_cors = [c for c in d["cors"] if c.get("severity") in ("critical", "high") and c.get("credentials_allowed")]
    if critical_cors and d["js_secrets"]:
        return {
            "name": "Credential-bearing CORS misconfig + high-confidence secrets on the same host",
            "severity": "critical",
            "host": host,
            "explanation": f"{len(critical_cors)} CORS finding(s) allow an attacker-controlled origin to read "
                            f"authenticated responses from this host, and {len(d['js_secrets'])} high-confidence "
                            "secret(s) were also found in this host's JS. An attacker origin could plausibly read "
                            "session data or exfiltrate these secrets via a victim's authenticated browser.",
        }
    return None


def rule_exposed_files_plus_secrets(host, d):
    accessible = [f for f in d["sensitive_files"] if f.get("status", 999) < 300]
    if accessible and d["js_secrets"]:
        return {
            "name": "Exposed sensitive file(s) + secrets independently confirmed in JS",
            "severity": "high",
            "host": host,
            "explanation": f"{len(accessible)} directly accessible sensitive file(s) (.git/.env/backup-type paths) "
                            f"plus {len(d['js_secrets'])} high-confidence secret(s) found via independent JS "
                            "analysis on the same host — two unrelated methods agreeing raises confidence this "
                            "host has a real credential-exposure problem, not a one-off false positive.",
        }
    return None


def rule_graphql_dangerous_mutations(host, d):
    dangerous_kw = ("delete", "remove", "drop", "admin", "impersonate", "export", "reset")
    for g in d["graphql"]:
        mutation_names = [m.get("name", "").lower() for m in g.get("mutations", [])]
        hits = [n for n in mutation_names if any(kw in n for kw in dangerous_kw)]
        if hits:
            return {
                "name": "GraphQL introspection enabled with dangerous-sounding mutations exposed",
                "severity": "high",
                "host": host,
                "explanation": f"Introspection revealed mutation(s) that sound high-impact: {', '.join(hits[:6])}. "
                                "Introspection being enabled in the first place is already worth flagging; having "
                                "visibility into destructive-sounding mutation names raises this further.",
            }
    return None


def rule_cicd_plus_cloud(host, d):
    if d["cicd_k8s"]:
        return {
            "name": "Exposed CI/CD or container config file",
            "severity": "high",
            "host": host,
            "explanation": f"{len(d['cicd_k8s'])} CI/CD or Docker/Kubernetes config file(s) are directly "
                            "accessible on this host. These commonly contain internal hostnames, registry URLs, "
                            "or (if misconfigured) credentials — review the actual file contents manually.",
        }
    return None


def rule_login_plus_known_usernames(host, d):
    if d["login_pages"] and d["wordpress"] and d["wordpress"].get("enumerated_usernames"):
        users = d["wordpress"]["enumerated_usernames"]
        return {
            "name": "Working login page + known usernames enumerated on the same host",
            "severity": "high",
            "host": host,
            "explanation": f"A confirmed login page exists on this host, and {len(users)} real username(s) were "
                            f"enumerated via the WordPress REST API: {', '.join(users[:10])}. This is a ready-made "
                            "target list for credential-stuffing or brute-force testing (check rate-limiting/lockout "
                            "policy before attempting) — far more actionable than either finding alone.",
        }
    return None


def rule_login_plus_ip_bypass(host, d):
    if d["login_pages"] and d["ip_bypass"]:
        return {
            "name": "Working login page on a host where IP restrictions were bypassed",
            "severity": "high",
            "host": host,
            "explanation": f"{len(d['login_pages'])} login page(s) confirmed on this host, and separately an "
                            "IP-restriction bypass was confirmed here too — worth checking whether the login flow "
                            "itself (or something behind it) is affected by the same bypassable access control.",
        }
    return None


def rule_confirmed_sqli(host, d):
    if d["sqli"]:
        params = [f"{s['parameter']} ({s['method']})" for s in d["sqli"]]
        dbms = next((s.get("dbms") for s in d["sqli"] if s.get("dbms")), None)
        return {
            "name": "Confirmed SQL injection (sqlmap, detection-only)",
            "severity": "critical",
            "host": host,
            "explanation": f"sqlmap confirmed {len(d['sqli'])} injectable parameter(s) on this host: "
                            f"{', '.join(params)}."
                            + (f" Back-end DBMS: {dbms}." if dbms else "")
                            + " No data was extracted (detection-only run) — this needs immediate manual follow-up.",
        }
    return None


def rule_sqli_plus_login(host, d):
    if d["sqli"] and d["login_pages"]:
        return {
            "name": "Confirmed SQL injection on a host with a working login page",
            "severity": "critical",
            "host": host,
            "explanation": "A confirmed, injectable parameter exists on the same host as a working login page — "
                            "worth specifically checking whether the injection point is reachable from the "
                            "authentication flow itself (classic SQLi auth bypass), not just elsewhere on the site.",
        }
    return None


def rule_confirmed_cmdi(host, d):
    if d["cmdi"]:
        params = [c.get("parameter") or "?" for c in d["cmdi"]]
        return {
            "name": "Confirmed OS command injection (commix, detection-only)",
            "severity": "critical",
            "host": host,
            "explanation": f"commix confirmed {len(d['cmdi'])} injectable parameter(s) on this host: "
                            f"{', '.join(params)}. No shell was opened and no data was read (detection-only run) — "
                            "this is one of the most severe vulnerability classes possible (potential full server "
                            "compromise) and needs immediate manual follow-up.",
        }
    return None


def rule_cmdi_plus_wordpress(host, d):
    if d["cmdi"] and d["wordpress"]:
        return {
            "name": "Confirmed command injection on a known WordPress host",
            "severity": "critical",
            "host": host,
            "explanation": "This host runs a fingerprinted WordPress install AND has a confirmed OS command "
                            "injection point. Worth checking whether the injectable parameter belongs to a "
                            "specific plugin/theme — that would let a fix (or a disclosure) target the exact "
                            "vulnerable component instead of just the symptom.",
        }
    return None


NAMED_RULES = [
    rule_wordpress_plus_cve,
    rule_admin_panel_plus_ip_bypass,
    rule_cors_plus_secrets,
    rule_exposed_files_plus_secrets,
    rule_graphql_dangerous_mutations,
    rule_cicd_plus_cloud,
    rule_login_plus_known_usernames,
    rule_login_plus_ip_bypass,
    rule_confirmed_sqli,
    rule_sqli_plus_login,
    rule_confirmed_cmdi,
    rule_cmdi_plus_wordpress,
]


def cumulative_score(d):
    score = 0
    score += len([f for f in d["sensitive_files"] if f.get("status", 999) < 300]) * WEIGHTS["sensitive_file"]
    score += len(d["content_discovery"]) * WEIGHTS["content_discovery_restricted"]
    score += len(d["ip_bypass"]) * WEIGHTS["ip_bypass"]
    score += len([c for c in d["cors"] if c.get("severity") in ("critical", "high")]) * WEIGHTS["cors_critical"]
    score += len([c for c in d["cors"] if c.get("severity") not in ("critical", "high")]) * WEIGHTS["cors_other"]
    score += len(d["misconfig"]) * WEIGHTS["misconfig"]
    score += (1 if d["wordpress"] else 0) * WEIGHTS["wordpress"]
    score += len(d["nuclei_critical"]) * WEIGHTS["nuclei_critical"]
    score += len(d["nuclei_exposures"]) * WEIGHTS["nuclei_exposure"]
    score += len(d["js_secrets"]) * WEIGHTS["js_secret_high"]
    score += len(d["cicd_k8s"]) * WEIGHTS["cicd_k8s_exposed"]
    score += len(d["graphql"]) * WEIGHTS["graphql_introspection"]
    score += len(d["login_pages"]) * WEIGHTS["login_page"]
    return score


def shodan_correlations():
    """Every Shodan asset with a known CVE is inherently a compound finding:
    an independent, external vulnerability database has already confirmed
    a real CVE on infrastructure genuinely belonging to this domain (matched
    via hostname/SSL cert, not a broad scan)."""
    data = read_json("report/shodan.json", {}) or {}
    findings = []
    for asset in data.get("hosts", []):
        if asset.get("vuln_count", 0) > 0:
            host_label = ", ".join(asset.get("hostnames") or []) or asset.get("ip")
            findings.append({
                "name": "Shodan-confirmed known CVE on target infrastructure",
                "severity": "critical" if asset["vuln_count"] > 1 else "high",
                "host": f"{asset.get('ip')}:{asset.get('port')} ({host_label})",
                "explanation": f"Shodan's own vulnerability database already lists {asset['vuln_count']} known "
                                f"CVE(s) for this asset: {', '.join(asset.get('known_cves', []))} — running "
                                f"{asset.get('product') or 'an unidentified service'}. This is an independent, "
                                "external confirmation, not a guess from this pipeline's own scanning.",
            })
    return findings


def main():
    host_data = build_host_data()
    correlations = []

    for host, d in host_data.items():
        if host == "__cloud__":
            continue
        for rule in NAMED_RULES:
            result = rule(host, d)
            if result:
                correlations.append(result)

    correlations.extend(shodan_correlations())

    # Generic cumulative-risk pass: hosts with many small findings across
    # different categories, even without a specific named pattern matching.
    THRESHOLD = 10
    for host, d in host_data.items():
        if host == "__cloud__":
            continue
        if any(c["host"] == host for c in correlations):
            continue  # already covered by a named rule, don't duplicate
        score = cumulative_score(d)
        if score >= THRESHOLD:
            categories_hit = [k for k in (
                "sensitive_files", "content_discovery", "ip_bypass", "cors",
                "misconfig", "nuclei_critical", "nuclei_exposures", "js_secrets", "cicd_k8s"
            ) if d[k]]
            correlations.append({
                "name": "Multiple independent findings accumulate on one host",
                "severity": "medium",
                "host": host,
                "explanation": f"No single finding here is critical alone, but {len(categories_hit)} different "
                                f"finding categories ({', '.join(categories_hit)}) hit the same host "
                                f"(cumulative score {score}). Worth a closer manual look as a whole.",
            })

    correlations.sort(key=lambda c: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(c["severity"], 4))

    os.makedirs("report", exist_ok=True)
    with open("report/correlations.json", "w") as f:
        json.dump({"total_correlations": len(correlations), "correlations": correlations}, f, indent=2)

    with open("report/correlations.txt", "w") as f:
        f.write(f"Total cross-referenced findings: {len(correlations)}\n\n")
        for c in correlations:
            f.write(f"[{c['severity'].upper()}] {c['name']}\n")
            f.write(f"    host: {c['host']}\n")
            f.write(f"    {c['explanation']}\n\n")

    print(f"  ✓ Correlation engine: {len(correlations)} compound-risk finding(s) -> report/correlations.*")


if __name__ == "__main__":
    main()