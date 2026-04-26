"""
Core detection logic.
Checks per-IP and global rates against the baseline.
Triggers bans and global alerts as needed.
"""
from baseline import Baseline
from blocker import ban_ip, is_banned
from notifier import alert_global
from config import CFG


class Detector:
    def __init__(self, window, baseline: Baseline):
        self.window = window
        self.baseline = baseline
        self._global_alerted = False

    def evaluate(self, ip):
        """Evaluate one IP after a new request is recorded."""
        if is_banned(ip):
            return

        ip_rate = self.window.ip_rate(ip)
        ip_error_rate = self.window.ip_error_rate(ip)
        global_rate = self.window.global_rate()

        mean = self.baseline.effective_mean
        stddev = self.baseline.effective_stddev

        # Tighten thresholds if IP has high error rate
        tightened = self.baseline.error_threshold_tightened(ip_error_rate)
        zscore_thresh = CFG["zscore_threshold"] * (0.5 if tightened else 1.0)
        mult_thresh = CFG["rate_multiplier_threshold"] * (0.5 if tightened else 1.0)

        # Per-IP check
        z = self.baseline.zscore(ip_rate)
        multiplier = ip_rate / mean if mean > 0 else 0

        if z > zscore_thresh or multiplier > mult_thresh:
            condition = (
                f"zscore={z:.2f} (thresh={zscore_thresh:.1f})"
                if z > zscore_thresh
                else f"rate={ip_rate:.2f} is {multiplier:.1f}x baseline"
            )
            ban_ip(ip, condition, ip_rate, mean)

        # Global check — alert only, no ban
        g_z = self.baseline.zscore(global_rate)
        g_mult = global_rate / mean if mean > 0 else 0

        if g_z > CFG["zscore_threshold"] or g_mult > CFG["rate_multiplier_threshold"]:
            if not self._global_alerted:
                condition = (
                    f"global zscore={g_z:.2f}"
                    if g_z > CFG["zscore_threshold"]
                    else f"global rate={global_rate:.2f} is {g_mult:.1f}x baseline"
                )
                alert_global(condition, global_rate, mean)
                self._global_alerted = True
        else:
            self._global_alerted = False
