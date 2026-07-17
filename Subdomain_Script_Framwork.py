#!/usr/bin/env python3
"""
generate_ai_report.py <domain> <model>

Reads the recon output files in the current working directory (the WORKDIR
created by recon-framework.sh), sends a condensed summary to the Claude API,
and writes report/attack_surface_report.html

Requires: ANTHROPIC_API_KEY env var, `requests` (pip install requests --break-system-packages)
"""
import os
import sys
import json
import html
import requests

API_URL = "https://api.anthropic.com/v1/messages"


def read_lines(path, limit=400):
    if not os.path.isfile(path):
        return []
    with open(path, "r", errors="ignore") as f:
        lines = [l.strip() for l in f if l.strip()]
    return lines[:limit]


def build_context(domain):
    ctx = {
        "domain": domain,
        "subdomains_sample": read_lines("all_subdomains.txt", 200),
        "subdomains_total": len(read_lines("all_subdomains.txt", 100000)),
        "live_hosts": read_lines("live/httpx_live.txt", 200),
        "live_total": len(read_lines("live/httpx_live.txt", 100000)),
        "nuclei_findings": read_lines("nuclei/nuclei_result.txt", 300),
        "nuclei_critical": read_lines("nuclei/nuclei_critical.txt", 200),
        "params_urls": read_lines("params/urls_with_params.txt", 150),
        "flagged_urls": read_lines("report/flagged.txt", 150),
        "takeover_results": read_lines("takeover/takeover-results.txt", 100),
        "js_files_count": len(
            [f for f in os.listdir("js") if f.endswith(".js")]
        ) if os.path.isdir("js") else 0,
    }
    return ctx


def call_claude(ctx, model):
    api_key = os.environ["ANTHROPIC_API_KEY"]

    prompt = f"""You are a senior application security engineer reviewing raw recon tool output
for the authorized bug bounty target: {ctx['domain']}

RAW DATA:
- Total subdomains found: {ctx['subdomains_total']}
- Sample subdomains: {json.dumps(ctx['subdomains_sample'][:100])}
- Live hosts (subset): {json.dumps(ctx['live_hosts'][:100])}
- Nuclei findings (all severities): {json.dumps(ctx['nuclei_findings'][:150])}
- Nuclei critical/high findings: {json.dumps(ctx['nuclei_critical'])}
- URLs with parameters (sample): {json.dumps(ctx['params_urls'][:80])}
- URLs flagged for sensitive keywords: {json.dumps(ctx['flagged_urls'][:80])}
- Subdomain takeover scan output: {json.dumps(ctx['takeover_results'])}
- Number of JS files harvested: {ctx['js_files_count']}

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
  "recommendations": ["string", "string"]
}}

Only include findings that are actually supported by the raw data given. Do not invent
vulnerabilities. If nuclei found nothing critical, say so plainly and keep risk_level
proportionate. Keep it concise and actionable for a bug bounty hunter deciding what to
manually test next."""

    resp = requests.post(
        API_URL,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": 4000,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=120,
    )
    resp.raise_for_status()
    data = resp.json()
    text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text.split("\n", 1)[1] if "\n" in text else text
        if text.endswith("json"):
            text = text[:-4]
    return json.loads(text)


SEVERITY_COLOR = {
    "critical": "#e11d48",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#22c55e",
}


def render_html(domain, report):
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
  <div class="subtitle">Target: <b>{html.escape(domain)}</b> — Generated by Claude</div>
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

  <div class="section-title">Interesting Endpoints</div>
  <table>{endpoints_html or "<tr><td>None flagged.</td></tr>"}</table>

  <div class="section-title">Recommendations</div>
  <ul>{recs_html or "<li>No specific recommendations generated.</li>"}</ul>
</div></body></html>"""


def main():
    if len(sys.argv) < 3:
        print("Usage: generate_ai_report.py <domain> <model>")
        sys.exit(1)
    domain, model = sys.argv[1], sys.argv[2]

    ctx = build_context(domain)
    print("  → sending recon summary to Claude for analysis...")
    report = call_claude(ctx, model)

    os.makedirs("report", exist_ok=True)
    out_path = "report/attack_surface_report.html"
    with open(out_path, "w") as f:
        f.write(render_html(domain, report))
    with open("report/attack_surface_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"  ✓ AI report written to {out_path}")


if __name__ == "__main__":
    main()