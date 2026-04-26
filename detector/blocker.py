"""
Manages iptables DROP rules for banned IPs.
"""
import subprocess
import time
import threading

from audit import write_audit
from notifier import alert_ban, alert_unban
from config import CFG

# ban_state: ip -> {"banned_at": float, "level": int, "duration_min": int}
_ban_state = {}
_lock = threading.Lock()

UNBAN_SCHEDULE = CFG["unban_schedule"]  # [10, 30, 120]


def ban_ip(ip, condition, rate, baseline):
    with _lock:
        if ip in _ban_state:
            return  # already banned

        level = 0
        duration_min = UNBAN_SCHEDULE[0]

        _iptables("I", ip)
        _ban_state[ip] = {
            "banned_at": time.time(),
            "level": level,
            "duration_min": duration_min,
        }

    alert_ban(ip, condition, rate, baseline, duration_min)
    write_audit(
        action="BAN",
        ip=ip,
        condition=condition,
        rate=rate,
        baseline=baseline,
        duration=f"{duration_min}min",
    )


def unban_ip(ip):
    with _lock:
        state = _ban_state.get(ip)
        if not state:
            return

        _iptables("D", ip)
        duration_min = state["duration_min"]
        level = state["level"]
        del _ban_state[ip]

    alert_unban(ip, duration_min)
    write_audit(
        action="UNBAN",
        ip=ip,
        condition="backoff_expired",
        rate=0,
        baseline=0,
        duration=f"{duration_min}min",
    )

    # If not at max level, re-ban with next backoff duration
    next_level = level + 1
    if next_level < len(UNBAN_SCHEDULE):
        next_duration = UNBAN_SCHEDULE[next_level]
        with _lock:
            _iptables("I", ip)
            _ban_state[ip] = {
                "banned_at": time.time(),
                "level": next_level,
                "duration_min": next_duration,
            }
        write_audit(
            action="REBAN",
            ip=ip,
            condition="backoff_reban",
            rate=0,
            baseline=0,
            duration=f"{next_duration}min",
        )


def check_unbans():
    """Called periodically to release expired bans."""
    now = time.time()
    to_unban = []
    with _lock:
        for ip, state in list(_ban_state.items()):
            elapsed_min = (now - state["banned_at"]) / 60
            if elapsed_min >= state["duration_min"]:
                to_unban.append(ip)

    for ip in to_unban:
        unban_ip(ip)


def is_banned(ip):
    with _lock:
        return ip in _ban_state


def banned_ips():
    with _lock:
        return dict(_ban_state)


def _iptables(action, ip):
    """Insert (I) or Delete (D) a DROP rule for ip."""
    try:
        subprocess.run(
            ["iptables", f"-{action}", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
    except subprocess.CalledProcessError as e:
        print(f"[blocker] iptables -{action} {ip} failed: {e.stderr.decode()}")
