"""
Rolling baseline using a 30-minute window of per-second request counts.

- Maintains per-hour slots so the current hour's data is preferred
  once it has enough samples.
- Recalculates mean and stddev every 60 seconds.
- Floor value prevents division-by-zero and over-sensitivity at low traffic.
"""
import math
import time
from collections import deque

from config import CFG


class Baseline:
    def __init__(self):
        self.window_minutes = CFG["baseline_window_minutes"]          # 30
        self.recalc_interval = CFG["baseline_recalc_interval_seconds"]  # 60
        self.min_samples = CFG["baseline_min_samples"]                # 10
        self.floor = CFG["baseline_floor_rps"]                        # 1.0

        # Rolling window: deque of (timestamp, per_second_count)
        # Each slot = one second bucket
        self._window = deque()

        # Per-hour slots: hour_key (int) -> list of per-second counts
        self._hourly = {}

        self.effective_mean = self.floor
        self.effective_stddev = 0.0
        self.effective_error_mean = 0.0
        self.effective_error_stddev = 0.0

        self._last_recalc = 0.0
        self._current_second = int(time.time())
        self._current_count = 0
        self._current_errors = 0

        # Error baseline
        self._error_window = deque()

    def record(self, is_error=False):
        """Called for every incoming request."""
        now_sec = int(time.time())
        if now_sec != self._current_second:
            self._flush_second(self._current_second,
                               self._current_count,
                               self._current_errors)
            self._current_second = now_sec
            self._current_count = 0
            self._current_errors = 0
        self._current_count += 1
        if is_error:
            self._current_errors += 1

        # Recalculate periodically
        if time.time() - self._last_recalc >= self.recalc_interval:
            self._recalculate()

    def _flush_second(self, ts, count, errors):
        cutoff = time.time() - self.window_minutes * 60
        self._window.append((ts, count))
        self._error_window.append((ts, errors))
        while self._window and self._window[0][0] < cutoff:
            self._window.popleft()
        while self._error_window and self._error_window[0][0] < cutoff:
            self._error_window.popleft()

        # Store in hourly slot
        hour_key = ts // 3600
        if hour_key not in self._hourly:
            self._hourly[hour_key] = []
        self._hourly[hour_key].append(count)

        # Keep only last 2 hours
        old_keys = [k for k in self._hourly if k < hour_key - 1]
        for k in old_keys:
            del self._hourly[k]

    def _recalculate(self):
        self._last_recalc = time.time()

        # Prefer current hour if it has enough data
        current_hour = int(time.time()) // 3600
        hourly_data = self._hourly.get(current_hour, [])

        if len(hourly_data) >= self.min_samples:
            samples = hourly_data
        else:
            # Fall back to full rolling window
            samples = [c for _, c in self._window]

        if len(samples) < self.min_samples:
            return  # Not enough data yet

        mean = sum(samples) / len(samples)
        variance = sum((x - mean) ** 2 for x in samples) / len(samples)
        stddev = math.sqrt(variance)

        self.effective_mean = max(mean, self.floor)
        self.effective_stddev = stddev

        # Error baseline
        error_samples = [c for _, c in self._error_window]
        if error_samples:
            emean = sum(error_samples) / len(error_samples)
            evar = sum((x - emean) ** 2 for x in error_samples) / len(error_samples)
            self.effective_error_mean = max(emean, 0.0)
            self.effective_error_stddev = math.sqrt(evar)

        from audit import write_audit
        write_audit(
            action="BASELINE_RECALC",
            ip="-",
            condition=f"samples={len(samples)}",
            rate=self.effective_mean,
            baseline=self.effective_mean,
            duration="-",
        )

    def zscore(self, rate):
        if self.effective_stddev == 0:
            return 0.0
        return (rate - self.effective_mean) / self.effective_stddev

    def is_anomalous(self, rate):
        """True if rate exceeds z-score threshold OR rate multiplier threshold."""
        z = self.zscore(rate)
        multiplier = rate / self.effective_mean if self.effective_mean > 0 else 0
        return (z > CFG["zscore_threshold"] or
                multiplier > CFG["rate_multiplier_threshold"])

    def error_threshold_tightened(self, ip_error_rate):
        """True if IP error rate is 3x the baseline error rate."""
        baseline_err = max(self.effective_error_mean, 0.01)
        return ip_error_rate > baseline_err * CFG["error_rate_multiplier"]
