"""
HNG Anomaly Detection Daemon
Entry point — wires all modules together and runs the main loop.
"""
import time
import sys
import subprocess

from config import CFG
from monitor import tail_log
from window import SlidingWindow
from baseline import Baseline
from detector import Detector
from unbanner import start_unbanner
from dashboard import start_dashboard, update_state

print("[main] Starting HNG anomaly detection daemon...")

# Ensure iptables default policy is ACCEPT so the server stays reachable.
# We only add per-IP DROP rules — never block all traffic by default.
try:
    subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], check=True, capture_output=True)
    subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], check=True, capture_output=True)
    subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=True, capture_output=True)
    print("[main] iptables default policy set to ACCEPT")
except Exception as e:
    print(f"[main] Warning: could not set iptables policy: {e}")

# Initialise components
window = SlidingWindow(window_seconds=CFG["per_ip_window_seconds"])
baseline = Baseline()
detector = Detector(window, baseline)

# Start background threads
start_unbanner()
start_dashboard()

print(f"[main] Dashboard at http://0.0.0.0:{CFG['dashboard_port']}")
print(f"[main] Tailing log: {CFG['log_path']}")

_last_state_update = 0
_logs_processed = 0

# Main loop — process log lines as they arrive
for entry in tail_log(CFG["log_path"]):
    ip = entry["source_ip"]
    is_error = entry["status"] >= 400
    _logs_processed += 1

    # Feed into sliding window and baseline
    window.record(ip, is_error=is_error)
    baseline.record(is_error=is_error)

    # Run detection
    detector.evaluate(ip)

    # Update dashboard state every second
    now = time.time()
    if now - _last_state_update >= 1.0:
        update_state(
            global_rps=window.global_rate(),
            top_ips=window.top_ips(10),
            mean=baseline.effective_mean,
            stddev=baseline.effective_stddev,
            logs_processed=_logs_processed,
        )
        _last_state_update = now
