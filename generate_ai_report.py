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
other evidence (e.g. a nuclei finding on the same host).

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