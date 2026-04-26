"""
Flask dashboard served at :8080
Refreshes every 3 seconds via meta-refresh and JS fetch.
Shows: banned IPs, global req/s, top 10 IPs, CPU/mem, baseline stats, uptime.
"""
import time
import threading
import psutil
from flask import Flask, jsonify, render_template_string

from blocker import banned_ips
from config import CFG

app = Flask(__name__)
_start_time = time.time()

# Shared state updated by main loop
_state = {
    "global_rps": 0.0,
    "top_ips": [],
    "mean": 0.0,
    "stddev": 0.0,
}

HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>HNG Anomaly Detector</title>
  <style>
    body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
    h1 { color: #58a6ff; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
    th, td { border: 1px solid #30363d; padding: 6px 12px; text-align: left; }
    th { background: #161b22; color: #58a6ff; }
    .badge-ban { color: #f85149; font-weight: bold; }
    .badge-ok  { color: #3fb950; }
    #updated { color: #8b949e; font-size: 0.85em; }
  </style>
  <script>
    async function refresh() {
      const r = await fetch('/api/status');
      const d = await r.json();
      document.getElementById('global_rps').innerText = d.global_rps.toFixed(2);
      document.getElementById('mean').innerText = d.mean.toFixed(2);
      document.getElementById('stddev').innerText = d.stddev.toFixed(2);
      document.getElementById('cpu').innerText = d.cpu_pct.toFixed(1);
      document.getElementById('mem').innerText = d.mem_pct.toFixed(1);
      document.getElementById('uptime').innerText = d.uptime;

      let banHtml = '';
      for (const [ip, info] of Object.entries(d.banned)) {
        banHtml += `<tr><td class="badge-ban">${ip}</td><td>${info.duration_min} min</td><td>${info.level}</td></tr>`;
      }
      document.getElementById('ban_body').innerHTML = banHtml || '<tr><td colspan=3 class="badge-ok">No bans</td></tr>';

      let ipHtml = '';
      for (const [ip, count] of d.top_ips) {
        ipHtml += `<tr><td>${ip}</td><td>${count}</td></tr>`;
      }
      document.getElementById('ip_body').innerHTML = ipHtml;

      document.getElementById('updated').innerText = 'Updated: ' + new Date().toISOString();
    }
    setInterval(refresh, 3000);
    refresh();
  </script>
</head>
<body>
  <h1>HNG Anomaly Detector — Live Dashboard</h1>
  <p id="updated"></p>

  <table>
    <tr><th>Metric</th><th>Value</th></tr>
    <tr><td>Global req/s</td><td id="global_rps">-</td></tr>
    <tr><td>Baseline mean (req/s)</td><td id="mean">-</td></tr>
    <tr><td>Baseline stddev</td><td id="stddev">-</td></tr>
    <tr><td>CPU %</td><td id="cpu">-</td></tr>
    <tr><td>Memory %</td><td id="mem">-</td></tr>
    <tr><td>Uptime</td><td id="uptime">-</td></tr>
  </table>

  <h2>Banned IPs</h2>
  <table>
    <thead><tr><th>IP</th><th>Duration</th><th>Ban Level</th></tr></thead>
    <tbody id="ban_body"></tbody>
  </table>

  <h2>Top 10 Source IPs (last 60s)</h2>
  <table>
    <thead><tr><th>IP</th><th>Requests</th></tr></thead>
    <tbody id="ip_body"></tbody>
  </table>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/status")
def status():
    uptime_sec = int(time.time() - _start_time)
    h, rem = divmod(uptime_sec, 3600)
    m, s = divmod(rem, 60)

    bans = {}
    for ip, info in banned_ips().items():
        bans[ip] = {
            "duration_min": info["duration_min"],
            "level": info["level"],
        }

    return jsonify({
        "global_rps": _state["global_rps"],
        "top_ips": _state["top_ips"],
        "mean": _state["mean"],
        "stddev": _state["stddev"],
        "cpu_pct": psutil.cpu_percent(),
        "mem_pct": psutil.virtual_memory().percent,
        "uptime": f"{h}h {m}m {s}s",
        "banned": bans,
    })


def update_state(global_rps, top_ips, mean, stddev):
    _state["global_rps"] = global_rps
    _state["top_ips"] = top_ips
    _state["mean"] = mean
    _state["stddev"] = stddev


def start_dashboard():
    t = threading.Thread(
        target=lambda: app.run(
            host=CFG["dashboard_host"],
            port=CFG["dashboard_port"],
            debug=False,
            use_reloader=False,
        ),
        daemon=True,
        name="dashboard",
    )
    t.start()
    return t
