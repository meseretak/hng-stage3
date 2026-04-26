# HNG Stage 3 — Anomaly Detection Engine

Real-time HTTP traffic anomaly detector running alongside Nextcloud.

**Server IP:** `136.115.145.233`
**Metrics Dashboard:** `http://136.115.145.233:8080`
**Language:** Python

---

## Why Python

Readable, fast to iterate, strong stdlib for deques and threading, psutil for system metrics, Flask for the dashboard.

---

## How the sliding window works

Each window is a `collections.deque` of `(timestamp, is_error)` tuples.

- On every request, a tuple is appended to the right
- On every read, entries older than 60 seconds are popped from the left
- Rate = `len(deque) / window_seconds`

Two windows run in parallel — one global, one per IP. No libraries, no counters.

---

## How the baseline works

- Every second, the current second request count is flushed into a rolling deque
- The deque covers the last 30 minutes of per-second counts
- Every 60 seconds, mean and stddev are recalculated from that window
- Per-hour slots are maintained — if the current hour has 10+ samples, it is preferred
- Floor value of 1.0 req/s prevents false positives at very low traffic

---

## How detection works

For each request, after updating the window:

1. Compute z-score: `(rate - mean) / stddev`
2. Compute multiplier: `rate / mean`
3. If z-score > 3.0 OR multiplier > 5.0 — anomalous
4. If IP error rate is 3x baseline error rate — thresholds halved (tightened)
5. Per-IP anomaly — iptables DROP + Slack alert within 10s
6. Global anomaly — Slack alert only

---

## Setup from a fresh VPS

```bash
# 1. Install Docker
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker

# 2. Clone repo
git clone https://github.com/meseretak/hng-stage3.git
cd hng-stage3

# 3. Configure
cp .env.example .env
# Edit .env — set SLACK_WEBHOOK_URL and SERVER_IP

# 4. Open firewall ports
sudo ufw allow 80/tcp
sudo ufw allow 8080/tcp

# 5. Start
docker compose up -d --build

# 6. Verify
docker compose ps
curl http://localhost/          # Nextcloud
curl http://localhost:8080/     # Dashboard
```

---

## Repository structure

```
detector/
  main.py         entry point, main loop
  monitor.py      log tailer and JSON parser
  window.py       deque-based sliding windows
  baseline.py     rolling baseline with hourly slots
  detector.py     anomaly detection logic
  blocker.py      iptables ban/unban management
  unbanner.py     background unban thread
  notifier.py     Slack alerts
  dashboard.py    Flask metrics dashboard
  audit.py        structured audit log writer
  config.py       config loader
  config.yaml     all thresholds and settings
  requirements.txt
  Dockerfile
nginx/
  nginx.conf      JSON access logs, real IP forwarding
docs/
  blog-post.md
  screenshots/
README.md
docker-compose.yml
.env.example
```

---

## Blog post

Full write-up covering sliding windows, baseline learning, detection logic, and iptables blocking:
https://dev.to/meseretak/hng-anomaly-detection-engine

---

## GitHub

https://github.com/meseretak/hng-stage3
