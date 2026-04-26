"""
Sends Slack alerts via incoming webhook.
"""
import time
import requests

from config import CFG


def _send(text):
    url = CFG.get("slack_webhook_url", "")
    if not url or url.startswith("$"):
        print(f"[slack] {text}")
        return
    try:
        requests.post(url, json={"text": text}, timeout=5)
    except Exception as e:
        print(f"[slack] failed to send: {e}")


def alert_ban(ip, condition, rate, baseline, duration_min):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _send(
        f":rotating_light: *BAN* `{ip}`\n"
        f"Condition: {condition}\n"
        f"Rate: {rate:.2f} req/s | Baseline: {baseline:.2f} req/s\n"
        f"Ban duration: {duration_min} min\n"
        f"Time: {ts}"
    )


def alert_unban(ip, duration_min):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _send(
        f":white_check_mark: *UNBAN* `{ip}`\n"
        f"Released after {duration_min} min ban\n"
        f"Time: {ts}"
    )


def alert_global(condition, rate, baseline):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _send(
        f":warning: *GLOBAL ANOMALY*\n"
        f"Condition: {condition}\n"
        f"Rate: {rate:.2f} req/s | Baseline: {baseline:.2f} req/s\n"
        f"Time: {ts}"
    )
