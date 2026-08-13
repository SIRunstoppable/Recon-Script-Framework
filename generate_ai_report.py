#!/usr/bin/env python3
"""
generate_ai_report.py <domain> <model>

Reads the recon output files in the current working directory (the WORKDIR
created by recon-framework.sh), sends a condensed summary to the Gemini API,
and writes report/attack_surface_report.html

Requires: GEMINI_API_KEY env var, `requests` (pip install requests --break-system-packages)

Note on <model>: pass a currently-valid Gemini model name (e.g. "gemini-2.0-flash").
Check https://ai.google.dev/gemini-api/docs/models for the current list — model
names get deprecated/renamed over time and this script does not try to guess.
"""
import os
import sys
import json
import html
import requests

API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"


def read_lines(path, limit=400):
    if not os.path.isfile(path):
        return []
    with open(path, "r", errors="ignore") as f:
        lines = [l.strip() for l in f if l.strip()]
    return lines[:limit]


def read_json(path, default=None):
    if not os.path.isfile(path):
        return default
    try:
        with open(path, "r", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return default


def build_context(domain):
    js_findings = read_json("report/js_findings.json", {}) or {}
    sensitive_findings = read_json("report/sensitive_files.json", {}) or {}
    param_flags = read_json("report/interesting_params.json", {}) or {}
    api_findings = read_json("report/api_endpoints.json", {}) or {}
    cors_findings = read_json("report/cors_headers.json", {}) or {}
    misconfig_findings = read_json("report/misconfig.json", {}) or {}
    cloud_findings = read_json("report/cloud_exposure.json", {}) or {}
    content_discovery = read_json("report/content_discovery.json", {}) or {}
    ip_bypass = read_json("report/ip_bypass.json", {}) or {}
    correlations = read_json("report/correlations.json", {}) or {}
    login_pages = read_json("report/login_pages.json", {}) or {}
    nikto_data = read_json("report/nikto.json", {}) or {}
    sqli_data = read_json("report/sqli_findings.json", {}) or {}
    waf_data = read_json("report/waf_detection.json", {}) or {}
    cmdi_data = read_json("report/cmdi_findings.json", {}) or {}
    juicy_data = read_json("report/juicy_files.json", {}) or {}
    shodan_data = read_json("report/shodan.json", {}) or {}
    source_map_findings = read_json("report/source_maps.json", {}) or {}
    wp_findings = read_json("report/wordpress.json", {}) or {}
    all_secrets = js_findings.get("secrets", [])
    high_conf_secrets = [s for s in all_secrets if s.get("confidence") == "high"][:100]
    low_conf_count = len([s for s in all_secrets if s.get("confidence") == "low"])
    ctx = {
        "domain": domain,
        "subdomains_sample": read_lines("all_subdomains.txt", 200),
        "subdomains_total": len(read_lines("all_subdomains.txt", 100000)),
        "live_hosts": read_lines("live/httpx_live.txt", 200),
        "live_total": len(read_lines("live/httpx_live.txt", 100000)),
        "nuclei_findings": read_lines("nuclei/nuclei_result.txt", 300),
        "nuclei_critical": read_lines("nuclei/nuclei_critical.txt", 200),
        "nuclei_exposures": read_lines("nuclei/nuclei_exposures.txt", 250),
        "params_urls": read_lines("params/urls_with_params.txt", 150),
        "flagged_urls": read_lines("report/flagged.txt", 150),
        "takeover_results": read_lines("takeover/takeover-results.txt", 100),
        "sensitive_files_accessible": [
            f for f in sensitive_findings.get("findings", []) if f.get("status", 999) < 300
        ][:100],
        "sensitive_files_protected_count": sensitive_findings.get("protected_count", 0),
        "open_redirect_flags": [e for e in param_flags.get("open_redirect", []) if e.get("signal") == "strong"],
        "ssrf_flags": [e for e in param_flags.get("ssrf", []) if e.get("signal") == "strong"],
        "idor_flags": [e for e in param_flags.get("idor", []) if e.get("signal") == "strong"],
        "openapi_specs": [
            {**s, "endpoints": s.get("endpoints", [])[:80]} for s in api_findings.get("openapi_specs", [])
        ][:20],
        "graphql_endpoints": [
            {**g, "queries": g.get("queries", [])[:40], "mutations": g.get("mutations", [])[:40]}
            for g in api_findings.get("graphql_endpoints", [])
        ][:20],
        "cors_findings": cors_findings.get("cors_findings", [])[:60],
        "hosts_missing_headers": cors_findings.get("hosts_missing_headers", [])[:60],
        "misconfig_findings": misconfig_findings.get("findings", [])[:150],
        "cloud_buckets_active": cloud_findings.get("buckets_found_active", []),
        "cloud_buckets_passive": cloud_findings.get("buckets_found_passive", []),
        "github_repos": cloud_findings.get("github_repos", [])[:10],
        "exposed_cicd_k8s_files": cloud_findings.get("exposed_cicd_k8s_files", [])[:60],
        "content_discovery": content_discovery.get("findings", [])[:150],
        "ip_bypass_findings": ip_bypass.get("findings", [])[:60],
        "correlations": correlations.get("correlations", []),
        "login_pages": login_pages.get("login_pages", [])[:60],
        "nikto_results": nikto_data.get("results", [])[:30],
        "sqli_findings": sqli_data.get("findings", []),
        "waf_detections": waf_data.get("detections", {}),
        "cmdi_findings": cmdi_data.get("findings", []),
        "juicy_files": juicy_data.get("files", [])[:80],
        "shodan_assets": shodan_data.get("hosts", [])[:60],
        "shodan_vuln_count": shodan_data.get("assets_with_known_cves", 0),
        "xss_findings": read_lines("nuclei/dalfox_xss.txt", 150),
        "source_maps_found": source_map_findings.get("maps_found", 0),
        "source_map_recovered_files": source_map_findings.get("total_recovered_files", 0),
        "source_map_secrets": [
            s for m in source_map_findings.get("maps", [])
            for s in m.get("secrets", []) if s.get("confidence") == "high"
        ][:60],
        "source_map_endpoints": [
            e for m in source_map_findings.get("maps", []) for e in m.get("endpoints", [])
        ][:100],
        "wordpress_sites": wp_findings.get("sites", []),
        "wordpress_nuclei_findings": read_lines("wordpress/nuclei_wordpress.txt", 150),
        "js_files_count": len(
            [f for f in os.listdir("js") if f.endswith(".js")]
        ) if os.path.isdir("js") else 0,
        "js_secrets_found": high_conf_secrets,
        "js_low_confidence_count": low_conf_count,
        "js_endpoints_found": js_findings.get("endpoints_sample", [])[:150],
        "js_total_endpoints": js_findings.get("total_unique_endpoints", 0),
    }
    return ctx


def build_prompt(ctx):
    return f"""You are a senior application security engineer reviewing raw recon tool output
for the authorized bug bounty target: {ctx['domain']}

PRE-VERIFIED CORRELATIONS (read this first): a deterministic rule-based engine already
cross-referenced findings across every scanning step, grouped by host, and flagged the
compound-risk patterns below BEFORE you saw any raw data. These are not guesses — each one
is backed by concrete evidence from two or more independent steps agreeing on the same host.
Give these priority placement in your priority_findings output; you don't need to re-derive
them, just incorporate them (you may still adjust severity slightly if the raw data below
gives you reason to, but explain why if you do):
{json.dumps(ctx['correlations'], indent=2)}

RAW DATA:
- Total subdomains found: {ctx['subdomains_total']}
- Sample subdomains: {json.dumps(ctx['subdomains_sample'][:100])}
- Live hosts (subset): {json.dumps(ctx['live_hosts'][:100])}
- Nuclei findings (all severities): {json.dumps(ctx['nuclei_findings'][:150])}
- Nuclei critical/high findings: {json.dumps(ctx['nuclei_critical'])}
- Nuclei "easy win" findings — exposure/misconfig/default-login/token/git/backup/exposed-panel tags (often rated info/low/medium severity by nuclei itself but frequently trivial to exploit — do not dismiss these just because of the low severity label): {json.dumps(ctx['nuclei_exposures'])}
- URLs with parameters (sample): {json.dumps(ctx['params_urls'][:80])}
- URLs flagged for sensitive keywords: {json.dumps(ctx['flagged_urls'][:80])}
- Subdomain takeover scan output: {json.dumps(ctx['takeover_results'])}
- Directly accessible sensitive files/paths found (e.g. .git, .env, backups, swagger, actuator — already baseline-filtered to remove soft-404 false positives): {json.dumps(ctx['sensitive_files_accessible'])}
- Additionally, {ctx['sensitive_files_protected_count']} sensitive paths exist but returned 401/403 (protected, still worth noting as attack surface)
- Strong-signal Open Redirect candidate parameters (name+value pattern matched, NOT confirmed — passive analysis only): {json.dumps(ctx['open_redirect_flags'])}
- Strong-signal SSRF candidate parameters (name+value pattern matched, NOT confirmed — passive analysis only): {json.dumps(ctx['ssrf_flags'])}
- Strong-signal IDOR candidate parameters (numeric ID in a likely-object-reference param, NOT confirmed — passive analysis only): {json.dumps(ctx['idor_flags'])}
- OpenAPI/Swagger specs discovered and parsed (real, documented API endpoints extracted directly from the target's own API docs — these ARE confirmed to exist, unlike the flags above): {json.dumps(ctx['openapi_specs'])}
- GraphQL endpoints where introspection is ENABLED (schema was successfully read — flag introspection-enabled-in-production as its own finding, then look at query/mutation names for anything sensitive like delete/admin/impersonate/export): {json.dumps(ctx['graphql_endpoints'])}
- CORS misconfigurations found (each is a confirmed, tested response header behavior — e.g. arbitrary Origin reflected back with credentials allowed): {json.dumps(ctx['cors_findings'])}
- Hosts missing baseline security headers (CSP/X-Frame-Options/HSTS/X-Content-Type-Options): {json.dumps(ctx['hosts_missing_headers'])}
- Security misconfiguration findings — CSP/HSTS/X-Frame-Options quality issues, insecure cookies (missing Secure/HttpOnly/SameSite), directory listing, debug headers/verbose Server banners, and exposed health/metrics endpoints (each already tagged with a severity by the scanner — treat those as a starting point, adjust if the evidence suggests otherwise): {json.dumps(ctx['misconfig_findings'])}
- Cloud storage buckets found via active name-guessing (confirmed to exist — "PUBLIC - listable" means fully open, "exists, access denied" just confirms the name is real): {json.dumps(ctx['cloud_buckets_active'])}
- Cloud storage bucket references found passively in the app's own collected URLs/JS (confirmed real usage, existence not separately verified): {json.dumps(ctx['cloud_buckets_passive'])}
- Public GitHub repositories matching the company/domain name (manual-review leads only — not inspected for actual secrets, just surfaced as candidates worth a human look): {json.dumps(ctx['github_repos'])}
- Exposed CI/CD or Docker/Kubernetes config files found on live hosts (each is a confirmed accessible file — treat as a real finding, especially if it might contain credentials or infra details): {json.dumps(ctx['exposed_cicd_k8s_files'])}
- Content discovery results (ffuf directory/file brute-force with auto-calibration against soft-404s — each entry is a confirmed accessible path not found through any other passive method; look especially for admin/internal/debug/backup-sounding paths and unusual status codes like 401/403 that hint at something worth auth-bypass testing): {json.dumps(ctx['content_discovery'])}
- CONFIRMED IP-restriction bypasses (a path that returned 401/403 normally but returned a different status when a spoofed IP header like X-Forwarded-For was sent — this is a real, confirmed access-control vulnerability, not a lead; rate high/critical depending on what the bypassed path appears to expose): {json.dumps(ctx['ip_bypass_findings'])}
- Working login pages found (confirmed live, high-confidence entries have an actual <input type="password"> field verified — these are good targets for manual testing of default creds, rate-limiting/brute-force protection, and MFA bypass; not vulnerabilities on their own, just confirmed attack-surface entry points worth listing as interesting_endpoints): {json.dumps(ctx['login_pages'])}
- Nikto web server scan findings (dangerous files, outdated server banners, common misconfigurations — a mix of severities, use judgment on what's actually notable vs routine): {json.dumps(ctx['nikto_results'])}
- CONFIRMED SQL injection points (sqlmap, detection-only run — no data was extracted, just confirmed the parameter is injectable; this is a serious, confirmed vulnerability and should generally be rated critical): {json.dumps(ctx['sqli_findings'])}
- WAF/CDN detected per host (purely informational context, NOT a finding — use this to explain why certain hosts may have returned thin/filtered results elsewhere in the scan, don't list it as a vulnerability): {json.dumps(ctx['waf_detections'])}
- CONFIRMED OS command injection points (commix, detection-only run — no shell was opened and no data/files were read, just confirmed the parameter executes injected commands; this is a critical, confirmed vulnerability, generally rate it critical): {json.dumps(ctx['cmdi_findings'])}
- "Juicy files" found — exposed backup/database/config files (.sql, .pak, .zip, .env, .db and variants), from both passive re-scanning of collected data and active probing with baseline soft-404 filtering (status/length null = found only passively, not independently confirmed by an active request; status present = confirmed accessible right now). These commonly contain credentials or full data dumps — rate high/critical depending on the extension (.env and .sql/.db dumps are usually more sensitive than a generic .zip): {json.dumps(ctx['juicy_files'])}
- Shodan-indexed assets belonging to this domain (found via hostname/SSL-cert match, scoped strictly to the target — NOT a broad internet scan). {ctx['shodan_vuln_count']} of these already have known CVEs per Shodan's own vulnerability database (see each asset's known_cves field). Treat known_cves as CONFIRMED, high-priority findings — these are publicly documented vulnerabilities on infrastructure this organization actually owns, often on IPs/ports the rest of the pipeline never touched (e.g. non-HTTP services): {json.dumps(ctx['shodan_assets'])}
- Dalfox XSS scan output (automated payload-based scan against parameterized URLs — findings here are generally strong signal but still worth a quick manual confirm): {json.dumps(ctx['xss_findings'])}
- Exposed source maps (.js.map) found: {ctx['source_maps_found']} (recovered {ctx['source_map_recovered_files']} original, unminified source files from them)
- High-confidence secrets found INSIDE recovered unminified source code (these came from real original source files, not minified bundles — generally more reliable than the minified-JS secret scan above): {json.dumps(ctx['source_map_secrets'])}
- Endpoints found inside recovered source maps: {json.dumps(ctx['source_map_endpoints'][:60])}
- WordPress sites detected (version, confirmed indicators, xmlrpc.php reachability, and any usernames enumerated via the public /wp-json/wp/v2/users endpoint — username enumeration and an old disclosed version are real findings on their own, even before any CVE match): {json.dumps(ctx['wordpress_sites'])}
- Nuclei WordPress-specific scan (core/plugin/theme CVE templates run only against confirmed WordPress hosts): {json.dumps(ctx['wordpress_nuclei_findings'])}
- Number of JS files harvested: {ctx['js_files_count']}
- HIGH-CONFIDENCE potential secrets found inside JS files (already filtered for entropy + placeholder patterns by a local scanner; format type/masked_value/confidence/reason/files): {json.dumps(ctx['js_secrets_found'])}
- Additionally, {ctx['js_low_confidence_count']} low-confidence JS matches were filtered out already (placeholders / low entropy) — do not ask about these, they were pre-screened as noise.
- Hidden endpoints extracted from JS files (sample): {json.dumps(ctx['js_endpoints_found'])}
- Total unique JS-derived endpoints: {ctx['js_total_endpoints']}

Note: JS secret values are masked (first/last few chars only) and were only pre-screened by
entropy/pattern heuristics, not manually verified — treat them as strong leads to manually
confirm, not certainties. Directly accessible sensitive files (.git, .env, backups, cloud
credential files, etc.) are usually serious findings on their own and should generally be
rated high/critical severity unless the specific file content is clearly non-sensitive. The
Open Redirect / SSRF / IDOR candidate parameters were flagged purely by name+value pattern
matching with zero requests sent — they are leads for manual testing, not confirmed
vulnerabilities. Phrase them as "candidate" or "worth testing" in your output, not as
confirmed bugs, and rate their severity moderately (medium at most) unless corroborated by
other evidence (e.g. a nuclei finding on the same host). CORS findings with
credentials_allowed=true reflecting an arbitrary origin are serious (high/critical); missing
security headers alone are low/informational unless paired with another finding that they'd
worsen (e.g. missing CSP alongside a confirmed XSS). Dalfox XSS output is an automated
payload-based scan (not just a name/value pattern flag) — treat it as strong signal, though
still note it should be manually confirmed before final reporting. An exposed source map that
recovers original source code is itself an information-disclosure finding worth listing (at
least low/medium) even before considering what's inside it — recovered secrets on top of that
push it higher. A cloud bucket marked "PUBLIC - listable" is a serious, confirmed finding
(high, or critical if it looks like it holds backups/user data/credentials); one marked
"exists, access denied" only confirms the name is real and is informational at most. GitHub
repos are unconfirmed manual-review leads, not findings — do not assign them a severity or
call them vulnerabilities, just list them as worth a human look. Exposed CI/CD/Docker/K8s
config files are confirmed accessible files; rate them based on what they'd likely contain
(a docker-compose.yml or CI workflow can leak credentials/infra details, so medium/high is
reasonable even without inspecting the exact contents shown).

TASK:
Produce a structured attack-surface assessment. Respond with ONLY valid JSON, no markdown
fences, no preamble, matching exactly this schema:

{{
  "executive_summary": "2-4 sentences, plain language overview of the attack surface",
  "risk_level": "low | medium | high | critical",
  "key_stats": {{"subdomains": int, "live_hosts": int, "critical_findings": int, "flagged_urls": int}},
  "priority_findings": [
    {{"title": "string", "severity": "low|medium|high|critical", "evidence": "string, cite the specific host/URL/finding", "why_it_matters": "string", "suggested_next_step": "string"}}
  ],
  "interesting_endpoints": [
    {{"url_or_host": "string", "reason": "string"}}
  ],
  "js_secrets_triage": [
    {{"type": "string", "masked_value": "string", "file": "string", "likely_real": true, "note": "string"}}
  ],
  "recommendations": ["string", "string"]
}}

Only include findings that are actually supported by the raw data given. Do not invent
vulnerabilities. If nuclei found nothing critical, say so plainly and keep risk_level
proportionate. Keep it concise and actionable for a bug bounty hunter deciding what to
manually test next."""


def call_gemini(ctx, model):
    api_key = os.environ["GEMINI_API_KEY"]
    url = f"{API_BASE}/{model}:generateContent?key={api_key}"

    payload = {
        "contents": [
            {"role": "user", "parts": [{"text": build_prompt(ctx)}]}
        ],
        "generationConfig": {
            "response_mime_type": "application/json",
            "temperature": 0.2,
            "maxOutputTokens": 8192,
        },
    }

    resp = requests.post(url, json=payload, timeout=120)
    if resp.status_code != 200:
        raise RuntimeError(f"Gemini API error {resp.status_code}: {resp.text[:500]}")
    data = resp.json()

    try:
        candidate = data["candidates"][0]
        parts = candidate["content"]["parts"]
        text = "".join(p.get("text", "") for p in parts).strip()
    except (KeyError, IndexError) as e:
        raise RuntimeError(f"Unexpected Gemini response shape: {json.dumps(data)[:800]}") from e

    if text.startswith("```"):
        text = text.strip("`")
        if "\n" in text:
            text = text.split("\n", 1)[1]
        if text.lower().startswith("json"):
            text = text[4:]

    return json.loads(text)


SEVERITY_COLOR = {
    "critical": "#e11d48",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#22c55e",
}


def render_html(domain, report, ctx):
    def sev_badge(sev):
        color = SEVERITY_COLOR.get(sev.lower(), "#6b7280")
        return f'<span style="background:{color};color:#fff;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600;text-transform:uppercase;">{html.escape(sev)}</span>'

    findings_html = ""
    for f in report.get("priority_findings", []):
        findings_html += f"""
        <div class="card">
          <div class="card-head">
            <span>{html.escape(f.get('title',''))}</span>
            {sev_badge(f.get('severity','low'))}
          </div>
          <div class="card-body">
            <p><b>Evidence:</b> <code>{html.escape(f.get('evidence',''))}</code></p>
            <p><b>Why it matters:</b> {html.escape(f.get('why_it_matters',''))}</p>
            <p><b>Next step:</b> {html.escape(f.get('suggested_next_step',''))}</p>
          </div>
        </div>"""

    endpoints_html = "".join(
        f"<tr><td><code>{html.escape(e.get('url_or_host',''))}</code></td><td>{html.escape(e.get('reason',''))}</td></tr>"
        for e in report.get("interesting_endpoints", [])
    )

    recs_html = "".join(f"<li>{html.escape(r)}</li>" for r in report.get("recommendations", []))

    sensitive_rows = "".join(
        f"<tr><td><code>{html.escape(f.get('url',''))}</code></td><td>{f.get('status','')}</td><td>{f.get('length','')}</td></tr>"
        for f in ctx.get("sensitive_files_accessible", [])
    )

    def param_rows(entries):
        rows = ""
        for e in entries:
            examples = "<br>".join(html.escape(u) for u in e.get("example_urls", [])[:3])
            rows += f"<tr><td><code>{html.escape(e.get('param',''))}</code></td><td>{examples}</td></tr>"
        return rows

    redirect_rows = param_rows(ctx.get("open_redirect_flags", []))
    ssrf_rows = param_rows(ctx.get("ssrf_flags", []))
    idor_rows = param_rows(ctx.get("idor_flags", []))

    cors_rows = ""
    for c in ctx.get("cors_findings", []):
        cors_rows += f"""<tr>
          <td>{sev_badge(c.get('severity','low'))}</td>
          <td><code>{html.escape(c.get('host',''))}</code></td>
          <td>{html.escape(c.get('test',''))}</td>
          <td>{'Yes' if c.get('credentials_allowed') else 'No'}</td>
          <td>{html.escape(c.get('note',''))}</td>
        </tr>"""

    headers_rows = "".join(
        f"<tr><td><code>{html.escape(h.get('host',''))}</code></td><td>{html.escape(', '.join(h.get('missing_headers', [])))}</td></tr>"
        for h in ctx.get("hosts_missing_headers", [])
    )

    source_map_rows = "".join(
        f"<tr><td>{html.escape(s.get('type',''))}</td><td><code>{html.escape(s.get('value_masked',''))}</code></td>"
        f"<td><code>{html.escape(s.get('source_file',''))}</code></td></tr>"
        for s in ctx.get("source_map_secrets", [])
    )

    wp_rows = ""
    for w in ctx.get("wordpress_sites", []):
        users = ", ".join(w.get("enumerated_usernames", [])) or "-"
        wp_rows += f"""<tr>
          <td><code>{html.escape(w.get('host',''))}</code></td>
          <td>{html.escape(w.get('version') or 'unknown')}</td>
          <td>{'Yes' if w.get('xmlrpc_enabled') else 'No'}</td>
          <td>{html.escape(users)}</td>
        </tr>"""

    misconfig_rows = ""
    for m in ctx.get("misconfig_findings", []):
        extra = m.get("url") or m.get("cookie") or ""
        detail = m.get("detail") or m.get("response_preview", "")
        misconfig_rows += f"""<tr>
          <td>{sev_badge(m.get('severity','low'))}</td>
          <td>{html.escape(m.get('category',''))}</td>
          <td><code>{html.escape(m.get('host',''))}</code> {html.escape(str(extra))}</td>
          <td>{html.escape(str(detail))[:200]}</td>
        </tr>"""

    bucket_rows = ""
    for b in ctx.get("cloud_buckets_active", []) + ctx.get("cloud_buckets_passive", []):
        bucket_rows += f"""<tr>
          <td>{html.escape(b.get('provider',''))}</td>
          <td><code>{html.escape(b.get('bucket',''))}</code></td>
          <td>{html.escape(b.get('status',''))}</td>
        </tr>"""

    github_rows = "".join(
        f"<tr><td><a href='{html.escape(r.get('url',''))}' style='color:#38bdf8;'>{html.escape(r.get('name',''))}</a></td>"
        f"<td>{r.get('stars','')}</td><td>{html.escape(r.get('description') or '')}</td></tr>"
        for r in ctx.get("github_repos", [])
    )

    cicd_rows = "".join(
        f"<tr><td><code>{html.escape(c.get('url',''))}</code></td><td>{c.get('length','')}</td></tr>"
        for c in ctx.get("exposed_cicd_k8s_files", [])
    )

    content_rows = "".join(
        f"<tr><td>{d.get('status','')}</td><td><code>{html.escape(d.get('url') or '')}</code></td><td>{d.get('length','')}</td></tr>"
        for d in ctx.get("content_discovery", [])
    )

    ip_bypass_rows = "".join(
        f"<tr><td><code>{html.escape(b.get('url',''))}</code></td><td>{b.get('baseline_status','')}</td><td>{b.get('bypassed_status','')}</td>"
        f"<td><code>{html.escape(b.get('bypass_header',''))}: {html.escape(b.get('bypass_value',''))}</code></td></tr>"
        for b in ctx.get("ip_bypass_findings", [])
    )

    correlation_rows = ""
    for c in ctx.get("correlations", []):
        correlation_rows += f"""<tr>
          <td>{sev_badge(c.get('severity','low'))}</td>
          <td>{html.escape(c.get('name',''))}</td>
          <td><code>{html.escape(c.get('host',''))}</code></td>
          <td>{html.escape(c.get('explanation',''))}</td>
        </tr>"""

    login_rows = "".join(
        f"<tr><td><code>{html.escape(l.get('url',''))}</code></td><td>{sev_badge('high' if l.get('confidence')=='high' else 'low')}</td></tr>"
        for l in ctx.get("login_pages", [])
    )

    sqli_rows = ""
    for s in ctx.get("sqli_findings", []):
        types_str = ", ".join(t.get("type", "") for t in s.get("types", []))
        sqli_rows += f"""<tr>
          <td><code>{html.escape(s.get('url') or '')}</code></td>
          <td><code>{html.escape(s.get('parameter',''))} ({html.escape(s.get('method',''))})</code></td>
          <td>{html.escape(s.get('dbms') or '?')}</td>
          <td>{html.escape(types_str)}</td>
        </tr>"""

    cmdi_rows = ""
    for c in ctx.get("cmdi_findings", []):
        cmdi_rows += f"""<tr>
          <td><code>{html.escape(c.get('url') or '')}</code></td>
          <td><code>{html.escape(c.get('parameter') or '?')}</code></td>
          <td>{html.escape(c.get('technique') or '?')}</td>
          <td>{html.escape(c.get('payload') or '?')}</td>
        </tr>"""

    juicy_rows = ""
    for j in ctx.get("juicy_files", []):
        confirmed = j.get("status") is not None and j.get("status", 999) < 300
        juicy_rows += f"""<tr>
          <td><code>{html.escape(j.get('url',''))}</code></td>
          <td>{sev_badge('high' if confirmed else 'low')}</td>
          <td>{html.escape(str(j.get('source') or ''))}</td>
        </tr>"""

    nikto_rows = ""
    for r in ctx.get("nikto_results", []):
        findings_preview = "; ".join(r.get("findings", [])[:5])
        nikto_rows += f"""<tr>
          <td>{html.escape(r.get('host_label',''))}</td>
          <td>{html.escape(findings_preview)}{' ...' if len(r.get('findings', [])) > 5 else ''}</td>
        </tr>"""

    waf_rows = ""
    for host, detections in ctx.get("waf_detections", {}).items():
        names = ", ".join(d.get("name", "") for d in detections)
        waf_rows += f"<tr><td><code>{html.escape(host)}</code></td><td>{html.escape(names)}</td></tr>"

    shodan_rows = ""
    for a in ctx.get("shodan_assets", []):
        cve_badge = sev_badge("critical" if a.get("vuln_count", 0) > 1 else ("high" if a.get("vuln_count") else "low"))
        shodan_rows += f"""<tr>
          <td><code>{html.escape(str(a.get('ip','')))}:{a.get('port','')}</code></td>
          <td>{html.escape(', '.join(a.get('hostnames') or []))}</td>
          <td>{html.escape(a.get('product') or '?')}</td>
          <td>{cve_badge} {html.escape(', '.join(a.get('known_cves') or []))}</td>
        </tr>"""

    js_rows = ""
    for s in report.get("js_secrets_triage", []):
        likely = s.get("likely_real", False)
        badge = sev_badge("high" if likely else "low")
        js_rows += f"""<tr>
          <td>{html.escape(s.get('type',''))}</td>
          <td><code>{html.escape(s.get('masked_value',''))}</code></td>
          <td><code>{html.escape(s.get('file',''))}</code></td>
          <td>{badge}</td>
          <td>{html.escape(s.get('note',''))}</td>
        </tr>"""

    stats = report.get("key_stats", {})
    risk = report.get("risk_level", "low")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Attack Surface Report - {html.escape(domain)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:40px; }}
  .container {{ max-width: 960px; margin: 0 auto; }}
  h1 {{ font-size: 28px; margin-bottom:4px; }}
  .subtitle {{ color:#94a3b8; margin-bottom:24px; }}
  .risk-banner {{ display:inline-block; padding:8px 20px; border-radius:8px; font-weight:700; margin-bottom:24px;
                  background:{SEVERITY_COLOR.get(risk.lower(), '#6b7280')}; color:#fff; }}
  .stats {{ display:flex; gap:16px; margin-bottom:28px; flex-wrap:wrap; }}
  .stat {{ background:#1e293b; border-radius:10px; padding:16px 20px; min-width:130px; }}
  .stat .num {{ font-size:24px; font-weight:700; }}
  .stat .label {{ color:#94a3b8; font-size:13px; }}
  .section-title {{ font-size:18px; font-weight:700; margin:32px 0 12px; border-bottom:1px solid #334155; padding-bottom:6px;}}
  .card {{ background:#1e293b; border-radius:10px; padding:16px 18px; margin-bottom:14px; }}
  .card-head {{ display:flex; justify-content:space-between; align-items:center; font-weight:700; margin-bottom:8px;}}
  .card-body p {{ margin:6px 0; font-size:14px; line-height:1.5;}}
  code {{ background:#0f172a; padding:1px 6px; border-radius:4px; font-size:12.5px; color:#38bdf8;}}
  table {{ width:100%; border-collapse:collapse; margin-bottom:20px;}}
  td {{ padding:8px 10px; border-bottom:1px solid #334155; font-size:13.5px; vertical-align:top;}}
  ul {{ font-size:14px; line-height:1.7;}}
  .exec {{ background:#1e293b; border-radius:10px; padding:18px 20px; font-size:15px; line-height:1.6;}}
</style></head>
<body><div class="container">
  <h1>🛡 Attack Surface Report</h1>
  <div class="subtitle">Target: <b>{html.escape(domain)}</b> — Generated by Gemini</div>
  <div class="risk-banner">Overall Risk: {html.escape(risk.upper())}</div>

  <div class="exec">{html.escape(report.get('executive_summary',''))}</div>

  <div class="stats">
    <div class="stat"><div class="num">{stats.get('subdomains','-')}</div><div class="label">Subdomains</div></div>
    <div class="stat"><div class="num">{stats.get('live_hosts','-')}</div><div class="label">Live Hosts</div></div>
    <div class="stat"><div class="num">{stats.get('critical_findings','-')}</div><div class="label">Critical Findings</div></div>
    <div class="stat"><div class="num">{stats.get('flagged_urls','-')}</div><div class="label">Flagged URLs</div></div>
  </div>

  <div class="section-title">🔗 Cross-Referenced Compound Findings</div>
  <p style="font-size:13px;color:#94a3b8;margin-top:-6px;">Deterministic rule-based correlation across every step's output, grouped by host — not AI-generated, verified by two or more independent methods agreeing.</p>
  <table>
    <tr><td><b>Severity</b></td><td><b>Pattern</b></td><td><b>Host</b></td><td><b>Why it matters</b></td></tr>
    {correlation_rows or "<tr><td colspan='4'>None found.</td></tr>"}
  </table>

  <div class="section-title">Priority Findings</div>
  {findings_html or "<p>No priority findings surfaced from raw data.</p>"}

  <div class="section-title">Exposed Sensitive Files</div>
  <table>
    <tr><td><b>URL</b></td><td><b>Status</b></td><td><b>Size (bytes)</b></td></tr>
    {sensitive_rows or "<tr><td colspan='3'>None found (baseline-filtered).</td></tr>"}
  </table>

  <div class="section-title">Interesting Endpoints</div>
  <table>{endpoints_html or "<tr><td>None flagged.</td></tr>"}</table>

  <div class="section-title">Candidate Params — Manual Testing Leads (unconfirmed)</div>
  <p style="font-size:13px;color:#94a3b8;margin-top:-6px;">Flagged by name/value pattern only — zero requests sent. Verify manually before reporting.</p>
  <table>
    <tr><td><b>Open Redirect</b></td><td><b>Example URLs</b></td></tr>
    {redirect_rows or "<tr><td colspan='2'>None flagged.</td></tr>"}
  </table>
  <table>
    <tr><td><b>SSRF</b></td><td><b>Example URLs</b></td></tr>
    {ssrf_rows or "<tr><td colspan='2'>None flagged.</td></tr>"}
  </table>
  <table>
    <tr><td><b>IDOR</b></td><td><b>Example URLs</b></td></tr>
    {idor_rows or "<tr><td colspan='2'>None flagged.</td></tr>"}
  </table>

  <div class="section-title">CORS Misconfigurations</div>
  <table>
    <tr><td><b>Severity</b></td><td><b>Host</b></td><td><b>Test</b></td><td><b>Credentials?</b></td><td><b>Note</b></td></tr>
    {cors_rows or "<tr><td colspan='5'>None found.</td></tr>"}
  </table>

  <div class="section-title">Missing Security Headers</div>
  <table>
    <tr><td><b>Host</b></td><td><b>Missing Headers</b></td></tr>
    {headers_rows or "<tr><td colspan='2'>None — all hosts have baseline headers.</td></tr>"}
  </table>

  <div class="section-title">Security Misconfigurations</div>
  <p style="font-size:13px;color:#94a3b8;margin-top:-6px;">CSP/HSTS/X-Frame-Options quality, insecure cookies, directory listing, debug headers, exposed health endpoints.</p>
  <table>
    <tr><td><b>Severity</b></td><td><b>Category</b></td><td><b>Host</b></td><td><b>Detail</b></td></tr>
    {misconfig_rows or "<tr><td colspan='4'>None found.</td></tr>"}
  </table>

  <div class="section-title">Cloud Storage Exposure (S3 / Azure)</div>
  <table>
    <tr><td><b>Provider</b></td><td><b>Bucket</b></td><td><b>Status</b></td></tr>
    {bucket_rows or "<tr><td colspan='3'>None found.</td></tr>"}
  </table>

  <div class="section-title">Related GitHub Repositories (manual review leads)</div>
  <table>
    <tr><td><b>Repo</b></td><td><b>★</b></td><td><b>Description</b></td></tr>
    {github_rows or "<tr><td colspan='3'>None found.</td></tr>"}
  </table>

  <div class="section-title">Exposed CI/CD & Docker/Kubernetes Configs</div>
  <table>
    <tr><td><b>URL</b></td><td><b>Size (bytes)</b></td></tr>
    {cicd_rows or "<tr><td colspan='2'>None found.</td></tr>"}
  </table>

  <div class="section-title">Content Discovery (ffuf)</div>
  <table>
    <tr><td><b>Status</b></td><td><b>URL</b></td><td><b>Size</b></td></tr>
    {content_rows or "<tr><td colspan='3'>None found (or ffuf not installed).</td></tr>"}
  </table>

  <div class="section-title">Confirmed IP-Restriction Bypasses</div>
  <p style="font-size:13px;color:#94a3b8;margin-top:-6px;">Paths that were 401/403 normally but returned a different status with a spoofed IP header (CWE-290).</p>
  <table>
    <tr><td><b>URL</b></td><td><b>Baseline</b></td><td><b>Bypassed</b></td><td><b>Via Header</b></td></tr>
    {ip_bypass_rows or "<tr><td colspan='4'>None found.</td></tr>"}
  </table>

  <div class="section-title">Working Login Pages</div>
  <p style="font-size:13px;color:#94a3b8;margin-top:-6px;">Confirmed live — good targets for manual credential/brute-force/MFA testing.</p>
  <table>
    <tr><td><b>URL</b></td><td><b>Confidence</b></td></tr>
    {login_rows or "<tr><td colspan='2'>None found.</td></tr>"}
  </table>

  <div class="section-title">Confirmed SQL Injection (sqlmap, detection-only)</div>
  <p style="font-size:13px;color:#94a3b8;margin-top:-6px;">--level=1 --risk=1, no data extracted — confirmed injectable parameters only.</p>
  <table>
    <tr><td><b>URL</b></td><td><b>Parameter</b></td><td><b>DBMS</b></td><td><b>Type(s)</b></td></tr>
    {sqli_rows or "<tr><td colspan='4'>None found.</td></tr>"}
  </table>

  <div class="section-title">Confirmed OS Command Injection (commix, detection-only)</div>
  <p style="font-size:13px;color:#94a3b8;margin-top:-6px;">--level=1, no shell opened / no data read — confirmed injectable parameters only.</p>
  <table>
    <tr><td><b>URL</b></td><td><b>Parameter</b></td><td><b>Technique</b></td><td><b>Payload</b></td></tr>
    {cmdi_rows or "<tr><td colspan='4'>None found.</td></tr>"}
  </table>

  <div class="section-title">Juicy Files (sql / pak / zip / env / db)</div>
  <p style="font-size:13px;color:#94a3b8;margin-top:-6px;">High-confidence = confirmed accessible right now (active probe). Low = seen in passively-collected data only, not independently re-confirmed.</p>
  <table>
    <tr><td><b>URL</b></td><td><b>Confidence</b></td><td><b>Source</b></td></tr>
    {juicy_rows or "<tr><td colspan='3'>None found.</td></tr>"}
  </table>

  <div class="section-title">Nikto Server Scan</div>
  <table>
    <tr><td><b>Host</b></td><td><b>Findings</b></td></tr>
    {nikto_rows or "<tr><td colspan='2'>None found (or nikto not installed).</td></tr>"}
  </table>

  <div class="section-title">WAF / CDN Detected</div>
  <p style="font-size:13px;color:#94a3b8;margin-top:-6px;">Informational only — explains why some hosts may show thinner scan results. Not a vulnerability.</p>
  <table>
    <tr><td><b>Host</b></td><td><b>WAF/CDN</b></td></tr>
    {waf_rows or "<tr><td colspan='2'>None detected.</td></tr>"}
  </table>

  <div class="section-title">Shodan Asset Discovery</div>
  <p style="font-size:13px;color:#94a3b8;margin-top:-6px;">Scoped to hostname/SSL-cert match for this domain only — known CVEs are Shodan's own vulnerability database, not actively exploited by this pipeline.</p>
  <table>
    <tr><td><b>IP:Port</b></td><td><b>Hostname(s)</b></td><td><b>Product</b></td><td><b>Known CVEs</b></td></tr>
    {shodan_rows or "<tr><td colspan='4'>None found (or SHODAN_API_KEY not set).</td></tr>"}
  </table>

  <div class="section-title">Secrets Recovered from Exposed Source Maps</div>
  <p style="font-size:13px;color:#94a3b8;margin-top:-6px;">Found: {ctx.get('source_maps_found',0)} exposed .js.map file(s), {ctx.get('source_map_recovered_files',0)} original source file(s) recovered.</p>
  <table>
    <tr><td><b>Type</b></td><td><b>Masked Value</b></td><td><b>Original Source File</b></td></tr>
    {source_map_rows or "<tr><td colspan='3'>None found.</td></tr>"}
  </table>

  <div class="section-title">WordPress Sites</div>
  <table>
    <tr><td><b>Host</b></td><td><b>Version</b></td><td><b>xmlrpc.php reachable</b></td><td><b>Usernames enumerated</b></td></tr>
    {wp_rows or "<tr><td colspan='4'>No WordPress sites detected.</td></tr>"}
  </table>

  <div class="section-title">JS Secrets Triage</div>
  <table>
    <tr><td><b>Type</b></td><td><b>Masked Value</b></td><td><b>File</b></td><td><b>Likely Real</b></td><td><b>Note</b></td></tr>
    {js_rows or "<tr><td colspan='5'>No JS secrets triaged.</td></tr>"}
  </table>

  <div class="section-title">Recommendations</div>
  <ul>{recs_html or "<li>No specific recommendations generated.</li>"}</ul>
</div></body></html>"""


def main():
    if len(sys.argv) < 3:
        print("Usage: generate_ai_report.py <domain> <model>")
        sys.exit(1)
    domain, model = sys.argv[1], sys.argv[2]

    ctx = build_context(domain)
    print(f"  → sending recon summary to Gemini ({model}) for analysis...")
    report = call_gemini(ctx, model)

    os.makedirs("report", exist_ok=True)
    out_path = "report/attack_surface_report.html"
    with open(out_path, "w") as f:
        f.write(render_html(domain, report, ctx))
    with open("report/attack_surface_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"  ✓ AI report written to {out_path}")


if __name__ == "__main__":
    main()