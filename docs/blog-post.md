# How I Built a Real-Time Anomaly Detection Engine for Nextcloud

When my boss said "build something that watches all incoming traffic and automatically blocks attackers," I had no idea where to start. This post walks through exactly how I built it — from reading log files line by line to blocking IPs with iptables — in a way that makes sense even if you've never touched security tooling before.

## What the project does

We have a Nextcloud instance (a file storage platform) running behind Nginx. The goal is to watch every HTTP request coming in, learn what "normal" traffic looks like, and automatically block any IP that starts behaving abnormally — like sending 500 requests per second when the normal rate is 2.

The system has four main jobs:
1. Read the Nginx access log in real time
2. Track request rates using sliding windows
3. Learn the baseline (what normal looks like)
4. Detect anomalies and block bad IPs

## How the sliding window works

Imagine a conveyor belt that's 60 seconds long. Every request that comes in gets placed on the right end of the belt. Every request older than 60 seconds falls off the left end automatically.

In Python, this is a `collections.deque`:

```python
from collections import deque
import time

window = deque()  # stores (timestamp, is_error) tuples

def record(ip):
    now = time.time()
    window.append((now, False))

def get_rate():
    cutoff = time.time() - 60
    # evict old entries from the left
    while window and window[0][0] < cutoff:
        window.popleft()
    return len(window) / 60  # requests per second
```

No libraries. No counters. Just a deque that evicts old entries on every read. We run one of these per IP and one globally.

## How the baseline learns from traffic

The baseline answers the question: "what does normal traffic look like right now?"

Every second, we record how many requests came in that second. We keep a rolling 30-minute history of these per-second counts. Every 60 seconds, we calculate the mean and standard deviation of that history.

```python
import math

samples = [2, 1, 3, 2, 1, 2, 3, 2, ...]  # per-second counts

mean = sum(samples) / len(samples)
variance = sum((x - mean)**2 for x in samples) / len(samples)
stddev = math.sqrt(variance)
```

We also keep per-hour slots. If the current hour has enough data, we prefer it over the full 30-minute window — because traffic at 3am looks different from traffic at 3pm.

A floor value of 1.0 req/s prevents false positives when traffic is very low.

## How the detection logic makes a decision

We use two checks — whichever fires first triggers a ban:

**Z-score check:** How many standard deviations above normal is this IP?
```python
z = (current_rate - baseline_mean) / baseline_stddev
if z > 3.0:
    ban(ip)
```

**Multiplier check:** Is this IP sending more than 5x the normal rate?
```python
if current_rate > baseline_mean * 5.0:
    ban(ip)
```

If an IP also has a high error rate (lots of 4xx/5xx responses), we tighten the thresholds — the z-score threshold drops from 3.0 to 1.5. This catches credential stuffing attacks that send many failed login attempts.

## How iptables blocks an IP

iptables is Linux's built-in firewall. When we detect an anomaly, we run:

```python
import subprocess

def ban_ip(ip):
    subprocess.run(
        ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
        check=True
    )
```

`-I INPUT` inserts a rule at the top of the INPUT chain. `-s` means "source IP". `-j DROP` means silently drop all packets from that IP. The connection just times out on the attacker's side — no response, no error.

Bans are temporary. We use a backoff schedule: 10 minutes, then 30 minutes, then 2 hours, then permanent. Each time the ban expires, if the IP was genuinely malicious it usually comes back — and gets a longer ban.

## The auto-unban system

A background thread checks every 30 seconds whether any ban has expired:

```python
import threading, time

def unban_loop():
    while True:
        for ip, state in list(banned_ips.items()):
            elapsed = (time.time() - state["banned_at"]) / 60
            if elapsed >= state["duration_min"]:
                remove_iptables_rule(ip)
                send_slack_alert(f"Unbanned {ip}")
        time.sleep(30)

threading.Thread(target=unban_loop, daemon=True).start()
```

## The live dashboard

A Flask web app runs on port 8080 and shows:
- Global requests per second
- Baseline mean and stddev
- Currently banned IPs
- Top 10 source IPs in the last 60 seconds
- CPU and memory usage
- Uptime

It refreshes every 3 seconds using JavaScript `fetch()` calls to `/api/status`.

## Why this matters

DDoS attacks and credential stuffing are real problems for any public-facing service. Most solutions either cost money (Cloudflare, AWS WAF) or require manual intervention. This tool runs entirely on your own server, learns your traffic patterns automatically, and responds within seconds — no human needed.

The key insight is that you don't need to know what an attack looks like in advance. You just need to know what normal looks like, and flag anything that deviates significantly.

## Stack

- Python 3.12
- Nginx (JSON access logs)
- Docker + Docker Compose
- iptables (blocking)
- Flask (dashboard)
- Slack webhooks (alerts)

## Links

- GitHub: https://github.com/meseretak/hng-stage3
- Dashboard: http://136.115.145.233:8080
