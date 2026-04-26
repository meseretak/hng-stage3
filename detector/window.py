"""
Deque-based sliding windows for per-IP and global request rate tracking.

Each window stores (timestamp, is_error) tuples.
Entries older than window_seconds are evicted on every read.
"""
import time
from collections import defaultdict, deque


class SlidingWindow:
    def __init__(self, window_seconds):
        self.window_seconds = window_seconds
        # global window: deque of (timestamp, is_error)
        self._global = deque()
        # per-ip windows: ip -> deque of (timestamp, is_error)
        self._per_ip = defaultdict(deque)

    def record(self, ip, is_error=False):
        """Record one request from ip."""
        now = time.time()
        self._global.append((now, is_error))
        self._per_ip[ip].append((now, is_error))

    def _evict(self, dq):
        """Remove entries older than window_seconds from the left of dq."""
        cutoff = time.time() - self.window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def global_rate(self):
        """Return current global requests/sec over the window."""
        self._evict(self._global)
        return len(self._global) / self.window_seconds

    def ip_rate(self, ip):
        """Return current req/s for a specific IP."""
        dq = self._per_ip[ip]
        self._evict(dq)
        return len(dq) / self.window_seconds

    def ip_error_rate(self, ip):
        """Return fraction of requests from ip that are 4xx/5xx."""
        dq = self._per_ip[ip]
        self._evict(dq)
        if not dq:
            return 0.0
        errors = sum(1 for _, e in dq if e)
        return errors / len(dq)

    def global_error_rate(self):
        self._evict(self._global)
        if not self._global:
            return 0.0
        errors = sum(1 for _, e in self._global if e)
        return errors / len(self._global)

    def top_ips(self, n=10):
        """Return top n IPs by current request count."""
        now = time.time()
        cutoff = now - self.window_seconds
        counts = {}
        for ip, dq in self._per_ip.items():
            self._evict(dq)
            counts[ip] = len(dq)
        return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def all_ips(self):
        return list(self._per_ip.keys())
