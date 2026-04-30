"""
Flask dashboard — modern UI with cards, charts, and live updates.
"""
import time
import threading
import psutil
from flask import Flask, jsonify, render_template_string, request

from blocker import banned_ips, ban_ip, unban_ip
from config import CFG

app = Flask(__name__)
_start_time = time.time()

_state = {
    "global_rps": 0.0,
    "top_ips": [],
    "mean": 0.0,
    "stddev": 0.0,
    "logs_processed": 0,
}

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HNG Anomaly Detector</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg:       #0d1117;
      --surface:  #161b22;
      --border:   #21262d;
      --blue:     #58a6ff;
      --green:    #3fb950;
      --red:      #f85149;
      --orange:   #e3b341;
      --grey:     #8b949e;
      --text:     #c9d1d9;
      --white:    #f0f6fc;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
    }

    /* ── Header ── */
    header {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 16px 28px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      position: sticky;
      top: 0;
      z-index: 100;
    }
    header h1 {
      font-size: 1.15rem;
      font-weight: 600;
      color: var(--white);
      display: flex;
      align-items: center;
      gap: 10px;
    }
    header h1 .dot {
      width: 10px; height: 10px;
      border-radius: 50%;
      background: var(--green);
      box-shadow: 0 0 8px var(--green);
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50%       { opacity: 0.4; }
    }
    #last-updated {
      font-size: 0.78rem;
      color: var(--grey);
    }

    /* ── Layout ── */
    main { padding: 24px 28px; max-width: 1400px; margin: 0 auto; }

    /* ── Stat cards ── */
    .cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 14px;
      margin-bottom: 24px;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 18px 20px;
      transition: border-color .2s;
    }
    .card:hover { border-color: var(--blue); }
    .card .label {
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: .06em;
      color: var(--grey);
      margin-bottom: 8px;
    }
    .card .value {
      font-size: 1.75rem;
      font-weight: 700;
      color: var(--white);
      line-height: 1;
    }
    .card .value.red    { color: var(--red); }
    .card .value.green  { color: var(--green); }
    .card .value.orange { color: var(--orange); }
    .card .bar-wrap {
      margin-top: 10px;
      height: 4px;
      background: var(--border);
      border-radius: 2px;
      overflow: hidden;
    }
    .card .bar {
      height: 100%;
      border-radius: 2px;
      background: var(--blue);
      transition: width .6s ease;
    }

    /* ── Baseline panel ── */
    .baseline {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px 20px;
      margin-bottom: 24px;
      display: flex;
      align-items: center;
      gap: 32px;
      flex-wrap: wrap;
    }
    .baseline .bl-title {
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: .06em;
      color: var(--grey);
      margin-bottom: 4px;
    }
    .baseline .bl-val {
      font-size: 1.1rem;
      font-weight: 600;
      color: var(--blue);
      font-family: monospace;
    }

    /* ── Two-column grid ── */
    .grid2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }
    @media (max-width: 900px) { .grid2 { grid-template-columns: 1fr; } }

    /* ── Panel ── */
    .panel {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
    }
    .panel-header {
      padding: 14px 20px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .panel-header h2 {
      font-size: 0.9rem;
      font-weight: 600;
      color: var(--white);
    }
    .badge {
      font-size: 0.72rem;
      padding: 2px 8px;
      border-radius: 20px;
      font-weight: 600;
    }
    .badge-red   { background: rgba(248,81,73,.15); color: var(--red); }
    .badge-green { background: rgba(63,185,80,.15); color: var(--green); }
    .badge-blue  { background: rgba(88,166,255,.15); color: var(--blue); }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
    }
    thead th {
      padding: 10px 20px;
      text-align: left;
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: .06em;
      color: var(--grey);
      background: rgba(255,255,255,.02);
      border-bottom: 1px solid var(--border);
    }
    tbody tr {
      border-bottom: 1px solid var(--border);
      transition: background .15s;
    }
    tbody tr:last-child { border-bottom: none; }
    tbody tr:hover { background: rgba(255,255,255,.03); }
    tbody td { padding: 10px 20px; }

    .ip-ban  { color: var(--red);   font-weight: 600; font-family: monospace; }
    .ip-ok   { color: var(--text);  font-family: monospace; }
    .level-0 { color: var(--orange); }
    .level-1 { color: var(--red); }
    .level-2 { color: #ff4444; font-weight: 700; }

    .empty-row td {
      text-align: center;
      color: var(--grey);
      padding: 24px;
      font-style: italic;
    }

    /* ── RPS sparkline ── */
    #sparkline-wrap {
      padding: 16px 20px 8px;
    }
    canvas#spark {
      width: 100%;
      height: 60px;
      display: block;
    }

    /* ── Threat meter ── */
    .threat-wrap {
      padding: 16px 20px;
      display: flex;
      align-items: center;
      gap: 16px;
    }
    .threat-label { font-size: 0.8rem; color: var(--grey); min-width: 60px; }
    .threat-bar-outer {
      flex: 1;
      height: 8px;
      background: var(--border);
      border-radius: 4px;
      overflow: hidden;
    }
    .threat-bar-inner {
      height: 100%;
      border-radius: 4px;
      transition: width .6s ease, background .6s ease;
    }
    .threat-value { font-size: 0.85rem; font-weight: 600; min-width: 48px; text-align: right; }
  </style>
</head>
<body>

<header>
  <h1>
    <span class="dot"></span>
    HNG Stage 3 — Anomaly Detection Dashboard
  </h1>
  <span id="last-updated">Connecting…</span>
</header>

<main>

  <!-- Stat cards -->
  <div class="cards">
    <div class="card">
      <div class="label">Global Req/s</div>
      <div class="value" id="c-rps">—</div>
    </div>
    <div class="card">
      <div class="label">Logs Processed</div>
      <div class="value green" id="c-logs">—</div>
    </div>
    <div class="card">
      <div class="label">Banned IPs</div>
      <div class="value red" id="c-bans">—</div>
    </div>
    <div class="card">
      <div class="label">Uptime</div>
      <div class="value" id="c-uptime">—</div>
    </div>
    <div class="card">
      <div class="label">CPU Usage</div>
      <div class="value" id="c-cpu">—</div>
      <div class="bar-wrap"><div class="bar" id="cpu-bar" style="width:0%"></div></div>
    </div>
    <div class="card">
      <div class="label">Memory Usage</div>
      <div class="value" id="c-mem">—</div>
      <div class="bar-wrap"><div class="bar" id="mem-bar" style="width:0%;background:var(--blue)"></div></div>
    </div>
  </div>

  <!-- Baseline -->
  <div class="baseline">
    <div>
      <div class="bl-title">Effective Baseline</div>
    </div>
    <div>
      <div class="bl-title">Mean</div>
      <div class="bl-val" id="b-mean">—</div>
    </div>
    <div>
      <div class="bl-title">Stddev</div>
      <div class="bl-val" id="b-stddev">—</div>
    </div>
    <div>
      <div class="bl-title">Z-score Threshold</div>
      <div class="bl-val">3.0</div>
    </div>
    <div>
      <div class="bl-title">Rate Multiplier</div>
      <div class="bl-val">5×</div>
    </div>
  </div>

  <!-- Two column -->
  <div class="grid2">

    <!-- Banned IPs -->
    <div class="panel">
      <div class="panel-header">
        <h2>🚫 Banned IPs</h2>
        <span class="badge badge-red" id="ban-count">0 active</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>IP Address</th>
            <th>Condition</th>
            <th>Rate (req/s)</th>
            <th>Baseline</th>
            <th>Duration</th>
            <th>Banned At</th>
          </tr>
        </thead>
        <tbody id="ban-body">
          <tr class="empty-row"><td colspan="6">No active bans — all clear</td></tr>
        </tbody>
      </table>
    </div>

    <!-- Top IPs -->
    <div class="panel">
      <div class="panel-header">
        <h2>📊 Top 10 Source IPs</h2>
        <span class="badge badge-blue">Last 60s</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>IP Address</th>
            <th>Total Requests Seen</th>
            <th>Activity</th>
          </tr>
        </thead>
        <tbody id="ip-body">
          <tr class="empty-row"><td colspan="3">No traffic yet</td></tr>
        </tbody>
      </table>
    </div>

  </div>

</main>

<script>
  const rpsHistory = [];
  const MAX_HIST = 40;

  function threatColor(level) {
    if (level === 0) return 'var(--orange)';
    if (level === 1) return 'var(--red)';
    return '#ff2222';
  }

  function levelLabel(level) {
    if (level === 0) return 'Warning';
    if (level === 1) return 'High';
    return 'Critical';
  }

  function barColor(pct) {
    if (pct > 80) return 'var(--red)';
    if (pct > 60) return 'var(--orange)';
    return 'var(--blue)';
  }

  async function refresh() {
    try {
      const r = await fetch('/api/status');
      const d = await r.json();

      // Cards
      document.getElementById('c-rps').textContent    = d.global_rps.toFixed(4);
      document.getElementById('c-logs').textContent   = (d.logs_processed || 0).toLocaleString();
      document.getElementById('c-uptime').textContent = d.uptime;

      const banCount = Object.keys(d.banned).length;
      document.getElementById('c-bans').textContent   = banCount;
      document.getElementById('ban-count').textContent = banCount + ' active';

      const cpu = d.cpu_pct.toFixed(1);
      const mem = d.mem_pct.toFixed(1);
      document.getElementById('c-cpu').textContent = cpu + '%';
      document.getElementById('c-mem').textContent = mem + '%';
      const cpuBar = document.getElementById('cpu-bar');
      const memBar = document.getElementById('mem-bar');
      cpuBar.style.width = cpu + '%';
      cpuBar.style.background = barColor(parseFloat(cpu));
      memBar.style.width = mem + '%';
      memBar.style.background = barColor(parseFloat(mem));

      // Baseline
      document.getElementById('b-mean').textContent   = d.mean.toFixed(4);
      document.getElementById('b-stddev').textContent = d.stddev.toFixed(4);

      // Banned IPs table
      const banBody = document.getElementById('ban-body');
      if (banCount === 0) {
        banBody.innerHTML = '<tr class="empty-row"><td colspan="6">No active bans — all clear ✅</td></tr>';
      } else {
        banBody.innerHTML = Object.entries(d.banned).map(([ip, info]) => `
          <tr>
            <td class="ip-ban">${ip}</td>
            <td style="font-size:0.8rem;color:var(--orange);max-width:220px;word-break:break-word">${info.condition}</td>
            <td style="font-family:monospace;color:var(--red)">${Number(info.rate).toFixed(4)}</td>
            <td style="font-family:monospace;color:var(--grey)">${Number(info.baseline).toFixed(4)}</td>
            <td><span class="badge badge-red">${info.duration_min} min</span></td>
            <td style="color:var(--grey);font-size:0.82rem">${info.banned_at}</td>
          </tr>`).join('');
      }

      // Top IPs table
      const ipBody = document.getElementById('ip-body');
      if (!d.top_ips || d.top_ips.length === 0) {
        ipBody.innerHTML = '<tr class="empty-row"><td colspan="3">No traffic yet</td></tr>';
      } else {
        const maxCount = d.top_ips[0][1] || 1;
        ipBody.innerHTML = d.top_ips.map(([ip, count]) => `
          <tr>
            <td class="ip-ok">${ip}</td>
            <td>${count}</td>
            <td>
              <div style="width:120px;height:6px;background:var(--border);border-radius:3px;overflow:hidden">
                <div style="width:${Math.round(count/maxCount*100)}%;height:100%;background:var(--blue);border-radius:3px;transition:width .4s"></div>
              </div>
            </td>
          </tr>`).join('');
      }

      document.getElementById('last-updated').textContent =
        'Live · Updated ' + new Date().toLocaleTimeString();

    } catch(e) {
      document.getElementById('last-updated').textContent = 'Connection error — retrying…';
    }
  }

  setInterval(refresh, 3000);
  refresh();
</script>
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
        banned_at_ts = info.get("banned_at", 0)
        bans[ip] = {
            "duration_min": info["duration_min"],
            "level":        info["level"],
            "condition":    info.get("condition", "—"),
            "rate":         info.get("rate", 0),
            "baseline":     info.get("baseline", 0),
            "banned_at":    time.strftime("%H:%M:%S", time.localtime(banned_at_ts)),
        }

    return jsonify({
        "global_rps":      _state["global_rps"],
        "top_ips":         _state["top_ips"],
        "mean":            _state["mean"],
        "stddev":          _state["stddev"],
        "logs_processed":  _state["logs_processed"],
        "cpu_pct":         psutil.cpu_percent(),
        "mem_pct":         psutil.virtual_memory().percent,
        "uptime":          f"{h}h {m}m {s}s",
        "banned":          bans,
    })


def update_state(global_rps, top_ips, mean, stddev, logs_processed=0):
    _state["global_rps"]     = global_rps
    _state["top_ips"]        = top_ips
    _state["mean"]           = mean
    _state["stddev"]         = stddev
    _state["logs_processed"] = logs_processed


@app.route("/api/ban", methods=["POST"])
def api_ban():
    """POST /api/ban  body: {"ip": "1.2.3.4"}"""
    data = request.get_json(force=True) or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400
    ban_ip(ip, "manual-ban via API", 99.0, 1.0)
    return jsonify({"status": "banned", "ip": ip})


@app.route("/api/unban", methods=["POST"])
def api_unban():
    """POST /api/unban  body: {"ip": "1.2.3.4"}"""
    data = request.get_json(force=True) or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400
    unban_ip(ip)
    return jsonify({"status": "unbanned", "ip": ip})


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
