# HNG Stage 3 — Anomaly Detection Engine

This is a real-time traffic anomaly detector I built for HNG Stage 3. It sits next to Nginx, watches every incoming request, figures out what "normal" traffic looks like, and automatically blocks IPs that go way beyond that — no manual intervention needed.

**Live dashboard:** http://136.115.145.233:8080
**Server:** 136.115.145.233
**Language:** Python

---

## The idea

Most rate limiters work with fixed thresholds — block anyone over 100 req/s, for example. The problem is that "normal" traffic varies a lot depending on the time of day, day of the week, and what your users are actually doing. A fixed threshold either lets real attacks through during quiet hours or blocks legitimate users during busy ones.

This tool learns your traffic patterns on the fly. It builds a rolling baseline from the last 30 minutes of real traffic, then flags anything that spikes more than 3 standard deviations above that — or more than 5x the mean. When something looks wrong, it drops the IP at the firewall level with an iptables rule and sends you a Slack message.

---

## How it works

### Watching the log

The detector tails the Nginx JSON access log line by line as requests come in. For each request it records the source IP, whether it was an error (status >= 400), and the timestamp.

### Sliding windows

Every IP gets its own sliding window — a deque of `(timestamp, is_error)` tuples covering the last 60 seconds. There's also a global window for all traffic combined. Old entries fall off the left side automatically. Rate is just `len(deque) / 60`. No external libraries, just Python deques.

### Baseline

Every second, the current global request count gets pushed into a 30-minute rolling deque. Every 60 seconds, mean and standard deviation are recalculated from that window. If the current hour has enough data, the hourly average is used instead — this handles predictable daily patterns better. The floor is 1.0 req/s so the system doesn't overreact during genuinely quiet periods.

### Detection

Two checks run on every request:

- **Z-score check:** if `(ip_rate - mean) / stddev > 3.0`, the IP gets banned
- **Multiplier check:** if `ip_rate > mean × 5`, the IP gets banned

If an IP also has a high error rate (lots of 4xx/5xx), both thresholds are cut in half — a scanner probing for vulnerabilities gets caught faster.

Global traffic spikes trigger a Slack alert but don't result in a ban, since you can't block "everyone."

### Bans and unbans

Bans are iptables DROP rules applied immediately. They expire on a backoff schedule:

1. First ban: 10 minutes
2. If the IP misbehaves again: 30 minutes
3. Third time: 2 hours
4. After that: permanent

Everything — bans, unbans, rebans — gets written to an audit log at `/var/log/detector/audit.log`.

### Dashboard

A Flask app runs on port 8080 and shows you what's happening right now: global req/s, the baseline mean and stddev, top 10 source IPs, currently banned IPs with their ban level and duration, and CPU/memory usage. It refreshes every 3 seconds.

---

## Stack

| Component | What it does |
|-----------|-------------|
| Nginx | Reverse proxy in front of Nextcloud, writes JSON access logs |
| Nextcloud | The app being protected |
| Detector | Python daemon — tails logs, runs detection, manages bans |
| Dashboard | Flask app showing live stats on port 8080 |

Everything runs in Docker. The detector container uses `network_mode: host` and the `NET_ADMIN` capability so it can actually run iptables commands.

---

## Getting started

```bash
git clone https://github.com/meseretak/hng-stage3.git
cd hng-stage3
cp .env.example .env
```

Open `.env` and fill in two things:

```
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/your/webhook/url
SERVER_IP=your.server.ip
```

Open the firewall ports and start everything:

```bash
sudo ufw allow 80/tcp
sudo ufw allow 8080/tcp
docker compose up -d --build
```

Check it's running:

```bash
docker compose ps
curl http://localhost:8080/api/status
```

You should see a JSON response with global req/s, baseline stats, and an empty banned list (hopefully).

---

## Tuning

The detection thresholds live in `detector/config.yaml`. The defaults work well for general web traffic but you can adjust them:

```yaml
zscore_threshold: 3.0          # how many stddevs above baseline = ban
rate_multiplier_threshold: 5.0 # how many times the mean = ban
error_rate_multiplier: 3.0     # tightening factor for high-error IPs
unban_schedule: [10, 30, 120]  # ban durations in minutes
baseline_window_minutes: 30    # how far back the baseline looks
```

---

## Repo layout

```
detector/   all Python source (main, detector, baseline, window, blocker, notifier, dashboard, audit, unbanner)
nginx/      nginx.conf configured for JSON logging
docs/       blog post and screenshots
docker-compose.yml
.env.example
```

---

## Blog post

https://dev.to/meseret_akalu_1743b6f6aa5/devops-track-3-4-20l2

## Repo
23https://github.com/meseretak/hng-stage3
