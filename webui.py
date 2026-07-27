#!/usr/bin/env python3
"""
webui.py — local web dashboard for recon-framework.sh

Runs a Flask server on localhost that lets you kick off scans, watch live
progress in the browser, browse past runs, and open the generated AI report
— without touching the terminal.

Usage:
    python3 webui.py
    # then open http://127.0.0.1:5050 in a browser

This drives recon-framework.sh via its CLI flags (--domain, --yes), so it
runs fully non-interactively. It does NOT bypass or weaken scope.txt
validation — --yes only auto-answers the same confirmation prompts you'd
answer at the terminal yourself; a domain that fails scope.txt validation
still hard-refuses to scan, same as the CLI.

Requires: flask (pip install flask --break-system-packages)
"""
import os
import re
import glob
import json
import queue
import shlex
import subprocess
import threading
import time
import uuid

from flask import Flask, Response, jsonify, request, send_file, abort

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RECON_SCRIPT = os.path.join(SCRIPT_DIR, "recon-framework.sh")

app = Flask(__name__)

# run_id -> {"proc": Popen, "queue": Queue, "domain": str, "workdir": str|None,
#            "status": "running"|"done"|"failed", "started_at": float}
RUNS = {}
RUNS_LOCK = threading.Lock()

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(s):
    return ANSI_RE.sub("", s)


def _reader_thread(run_id, proc):
    """Reads the subprocess's combined stdout/stderr line-by-line (a "line"
    here is whatever's flushed between newlines — the bash script's \r-based
    spinner updates all arrive as one chunk containing multiple \r's; we
    split on \r and keep only the final segment, so the browser sees each
    step's *final* state rather than every intermediate spinner frame)."""
    q = RUNS[run_id]["queue"]
    workdir_re = re.compile(r"(?:Resuming|Starting fresh run): (\S+)")

    for raw_line in iter(proc.stdout.readline, ""):
        if not raw_line:
            break
        clean = strip_ansi(raw_line).rstrip("\n")
        # collapse spinner \r-updates down to the final frame
        if "\r" in clean:
            parts = [p for p in clean.split("\r") if p.strip()]
            clean = parts[-1] if parts else ""
        if not clean.strip():
            continue

        m = workdir_re.search(clean)
        if m:
            with RUNS_LOCK:
                RUNS[run_id]["workdir"] = m.group(1)

        q.put(clean)

    proc.wait()
    with RUNS_LOCK:
        RUNS[run_id]["status"] = "done" if proc.returncode == 0 else "failed"
    q.put("__DONE__")


@app.route("/")
def index():
    return INDEX_HTML


@app.route("/api/start", methods=["POST"])
def api_start():
    data = request.get_json(force=True) or {}
    domain = (data.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "domain is required"}), 400
    # very light sanity check — real validation happens in scope.txt via the script itself
    if not re.match(r"^[a-zA-Z0-9.\-]+$", domain):
        return jsonify({"error": "domain looks invalid"}), 400

    run_id = uuid.uuid4().hex[:12]
    cmd = ["bash", RECON_SCRIPT, "--domain", domain, "--yes"]

    proc = subprocess.Popen(
        cmd,
        cwd=SCRIPT_DIR,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    with RUNS_LOCK:
        RUNS[run_id] = {
            "proc": proc,
            "queue": queue.Queue(),
            "domain": domain,
            "workdir": None,
            "status": "running",
            "started_at": time.time(),
        }

    threading.Thread(target=_reader_thread, args=(run_id, proc), daemon=True).start()
    return jsonify({"run_id": run_id})


@app.route("/api/stream/<run_id>")
def api_stream(run_id):
    if run_id not in RUNS:
        abort(404)

    def generate():
        q = RUNS[run_id]["queue"]
        while True:
            line = q.get()
            if line == "__DONE__":
                status = RUNS[run_id]["status"]
                workdir = RUNS[run_id]["workdir"]
                yield f"event: done\ndata: {json.dumps({'status': status, 'workdir': workdir})}\n\n"
                break
            yield f"data: {json.dumps(line)}\n\n"

    return Response(generate(), mimetype="text/event-stream")


@app.route("/api/runs")
def api_runs():
    runs = []
    for path in sorted(glob.glob(os.path.join(SCRIPT_DIR, "recon-*-*")), reverse=True):
        if not os.path.isdir(path):
            continue
        name = os.path.basename(path)
        checkpoint_file = os.path.join(path, ".checkpoint")
        completed = 0
        if os.path.isfile(checkpoint_file):
            with open(checkpoint_file) as f:
                completed = len([l for l in f if l.strip()])
        report_path = os.path.join(path, "report", "attack_surface_report.html")
        runs.append({
            "name": name,
            "completed_steps": completed,
            "has_report": os.path.isfile(report_path),
        })
    return jsonify(runs)


@app.route("/report/<run_name>")
def view_report(run_name):
    # basic path-safety: only allow simple folder names, no traversal
    if not re.match(r"^[a-zA-Z0-9._\-]+$", run_name):
        abort(400)
    report_path = os.path.join(SCRIPT_DIR, run_name, "report", "attack_surface_report.html")
    if not os.path.isfile(report_path):
        abort(404)
    return send_file(report_path)


INDEX_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Recon Framework Dashboard</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:32px; }
  .container { max-width: 920px; margin: 0 auto; }
  h1 { font-size: 24px; margin-bottom: 4px; }
  .subtitle { color:#94a3b8; margin-bottom: 24px; font-size: 14px; }
  .card { background:#1e293b; border-radius: 10px; padding: 20px; margin-bottom: 20px; }
  input[type=text] { background:#0f172a; border:1px solid #334155; color:#e2e8f0; padding:10px 12px; border-radius:6px; font-size:14px; width: 320px; }
  button { background:#2563eb; color:#fff; border:none; padding:10px 18px; border-radius:6px; font-size:14px; cursor:pointer; font-weight:600; }
  button:hover { background:#1d4ed8; }
  button:disabled { background:#475569; cursor:not-allowed; }
  #log { background:#000; color:#4ade80; font-family: ui-monospace, monospace; font-size: 13px; padding:16px; border-radius:8px; height:420px; overflow-y:auto; white-space:pre-wrap; }
  .runs-table { width:100%; border-collapse:collapse; }
  .runs-table td { padding:10px 8px; border-bottom:1px solid #334155; font-size:14px; }
  .badge { padding:2px 10px; border-radius:10px; font-size:12px; font-weight:600; }
  .badge-done { background:#16a34a; color:#fff; }
  .badge-partial { background:#ca8a04; color:#fff; }
  a.report-link { color:#38bdf8; text-decoration:none; font-weight:600; }
  a.report-link:hover { text-decoration:underline; }
  .status-line { font-size:13px; color:#94a3b8; margin-top:8px; }
</style></head>
<body>
<div class="container">
  <h1>🛡 Recon Framework Dashboard</h1>
  <div class="subtitle">Authorized bug bounty / pentest recon only — domain must be covered by scope.txt.</div>

  <div class="card">
    <div style="display:flex; gap:12px; align-items:center;">
      <input type="text" id="domainInput" placeholder="example.com">
      <button id="startBtn" onclick="startScan()">Start Scan</button>
    </div>
    <div class="status-line" id="statusLine"></div>
  </div>

  <div class="card">
    <div id="log">Waiting for a scan to start...</div>
  </div>

  <div class="card">
    <h3 style="margin-top:0;">Past Runs</h3>
    <table class="runs-table" id="runsTable"><tbody></tbody></table>
  </div>
</div>

<script>
let currentRunId = null;

async function startScan() {
  const domain = document.getElementById('domainInput').value.trim();
  if (!domain) { alert('Enter a domain first'); return; }
  document.getElementById('startBtn').disabled = true;
  document.getElementById('statusLine').textContent = 'Starting...';
  document.getElementById('log').textContent = '';

  const res = await fetch('/api/start', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({domain})
  });
  const data = await res.json();
  if (data.error) {
    alert(data.error);
    document.getElementById('startBtn').disabled = false;
    return;
  }
  currentRunId = data.run_id;
  streamLog(currentRunId);
}

function streamLog(runId) {
  const log = document.getElementById('log');
  const evtSource = new EventSource('/api/stream/' + runId);

  evtSource.onmessage = (e) => {
    const line = JSON.parse(e.data);
    log.textContent += line + '\\n';
    log.scrollTop = log.scrollHeight;
  };

  evtSource.addEventListener('done', (e) => {
    const info = JSON.parse(e.data);
    document.getElementById('statusLine').textContent =
      'Finished: ' + info.status + (info.workdir ? ' (' + info.workdir + ')' : '');
    document.getElementById('startBtn').disabled = false;
    evtSource.close();
    loadRuns();
  });

  evtSource.onerror = () => {
    document.getElementById('statusLine').textContent = 'Stream disconnected.';
    document.getElementById('startBtn').disabled = false;
    evtSource.close();
  };
}

async function loadRuns() {
  const res = await fetch('/api/runs');
  const runs = await res.json();
  const tbody = document.querySelector('#runsTable tbody');
  tbody.innerHTML = '';
  for (const run of runs) {
    const tr = document.createElement('tr');
    const badge = run.has_report
      ? '<span class="badge badge-done">done</span>'
      : '<span class="badge badge-partial">' + run.completed_steps + ' steps</span>';
    const reportLink = run.has_report
      ? '<a class="report-link" href="/report/' + run.name + '" target="_blank">Open report ↗</a>'
      : '<span style="color:#64748b;">no report yet</span>';
    tr.innerHTML = '<td>' + run.name + '</td><td>' + badge + '</td><td>' + reportLink + '</td>';
    tbody.appendChild(tr);
  }
}

loadRuns();
setInterval(loadRuns, 10000);
</script>
</body></html>
"""

if __name__ == "__main__":
    print("Recon Framework Dashboard: http://127.0.0.1:5050")
    app.run(host="127.0.0.1", port=5050, debug=False, threaded=True)
