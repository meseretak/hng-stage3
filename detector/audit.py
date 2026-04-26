"""
Structured audit log writer.
Format: [timestamp] ACTION ip | condition | rate | baseline | duration
"""
import os
import time

from config import CFG

_log_path = CFG.get("audit_log_path", "/var/log/detector/audit.log")


def write_audit(action, ip, condition, rate, baseline, duration):
    os.makedirs(os.path.dirname(_log_path), exist_ok=True)
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = (
        f"[{ts}] {action} {ip} | {condition} | "
        f"rate={rate:.2f} | baseline={baseline:.2f} | duration={duration}\n"
    )
    with open(_log_path, "a") as f:
        f.write(line)
    print(line.strip())
