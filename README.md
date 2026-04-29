# HNG Stage 3 — Anomaly Detection Engine

**Dashboard:** http://meseret-hng.servequake.com/dashboard/
**Server:** 35.223.71.226
**Language:** Python

---

I built this for HNG Stage 3. The task was to watch Nginx traffic in real time, learn what normal looks like, and block anything that looks like an attack — automatically, without any manual intervention.

The core idea is simple: instead of hardcoding a threshold like "block anyone over 100 req/s", the tool watches actual traffic and builds a picture of what normal looks like. Then it reacts when something deviates from that picture.

---

## What it does

- Tails the Nginx JSON access log line by line as requests come in
- Tracks request rates per IP and globally using sliding windows (deques, last 60 seconds)
- Builds a rolling baseline from the last 30 minutes of traffic — recalculates mean and stddev every 60 seconds
- If the current hour has enough data, uses that instead of the full window (handles daily traffic patterns)
- Flags anything that spikes above 3x stddev or 5x the mean — whichever fires first
- If an IP has a high error rate (4xx/5xx), thresholds are cut in half automatically
- Blocks bad IPs with iptables DROP rules within 10 seconds
- Sends Slack alerts on ban and unban
- Releases bans on a backoff schedule: 10 min → 30 min → 2 hours → permanent
- Shows everything on a live web dashboard that refreshes every 3 seconds

---

## How the sliding window works

Each window is a `deque` of `(timestamp, is_error)` tuples. New requests go on the right. On every read, anything older than 60 seconds gets popped from the left. Rate = `len(deque) / 60`. One deque per IP, one global. No libraries — just Python's built-in `collections.deque`.

---

## How the baseline works

Every second I flush the current request count into a rolling 30-minute deque. Every 60 seconds I recalculate mean and stddev from that window. I also keep per-hour slots — if the current hour has at least 10 samples I use that instead of the full window. Floor is 1.0 req/s so it doesn't go crazy on low traffic.

---

## Repo layout

```
detector/
  main.py        wires everything together, runs the main loop
  monitor.py     tails and parses the Nginx JSON log
  window.py      sliding window per IP and global
  baseline.py    rolling baseline with hourly slots
  detector.py    detection logic — z-score and multiplier checks
  blocker.py     iptables DROP rules and ban state
  unbanner.py    background thread that checks for expired bans
  notifier.py    Slack webhook alerts
  dashboard.py   Flask live metrics UI
  audit.py       writes structured audit log entries
  config.py      loads config.yaml
  config.yaml    all thresholds and settings
  requirements.txt
  Dockerfile
nginx/
  nginx.conf
docs/
  architecture.png
  blog-post.md
  screenshots/
docker-compose.yml
.env.example
```

---

## Setup from scratch

```bash
git clone https://github.com/meseretak/hng-stage3.git
cd hng-stage3
cp .env.example .env
```

Edit `.env`:
```
SLACK_WEBHOOK_URL=your_slack_webhook_url
SERVER_IP=your_server_ip
NEXTCLOUD_ADMIN_USER=admin
NEXTCLOUD_ADMIN_PASSWORD=your_password
```

Switch iptables to legacy mode (needed for Docker + iptables to work together):
```bash
sudo update-alternatives --set iptables /usr/sbin/iptables-legacy
sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
```

Start everything:
```bash
docker compose up -d --build
```

Check it's running:
```bash
docker compose ps
curl http://localhost/api/status
```

If Nextcloud shows "untrusted domain", add your IP:
```bash
docker exec -u 33 hng-stage3-nextcloud-1 php /var/www/html/occ config:system:set trusted_domains 0 --value="your_server_ip"
```

---

## Thresholds (all in config.yaml)

```yaml
zscore_threshold: 3.0
rate_multiplier_threshold: 5.0
error_rate_multiplier: 3.0
unban_schedule: [10, 30, 120]
baseline_window_minutes: 30
baseline_floor_rps: 1.0
```

---

## Screenshots

| | |
|---|---|
| ![Tool running](docs/screenshots/Tool-running.png) | Daemon running |
| ![iptables](docs/screenshots/Iptables-banned.png) | Blocked IP in iptables |
| ![Audit log](docs/screenshots/Audit-log.png) | Audit log entries |
| ![Ban slack](docs/screenshots/Ban-slack.png) | Slack ban alert |
| ![Unban slack](docs/screenshots/Unban-slack.png) | Slack unban alert |

---

## Blog post

https://dev.to/meseret_akalu_1743b6f6aa5/devops-track-3-4-20l2

## Repo

https://github.com/meseretak/hng-stage3
