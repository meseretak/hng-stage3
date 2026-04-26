"""
Continuously tails the Nginx JSON access log.
Yields parsed log entry dicts to the caller.
"""
import json
import time
import os


def tail_log(path):
    """
    Open the log file and yield new lines as they appear.
    Handles log rotation by re-opening when the file shrinks.
    """
    while not os.path.exists(path):
        print(f"[monitor] waiting for log file: {path}")
        time.sleep(2)

    with open(path) as f:
        # Seek to end on startup — don't replay old entries
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                entry = parse_line(line.strip())
                if entry:
                    yield entry
            else:
                # Check for rotation (file shrunk)
                try:
                    if os.path.getsize(path) < f.tell():
                        f.seek(0)
                except OSError:
                    pass
                time.sleep(0.05)


def parse_line(line):
    """Parse a single JSON log line into a dict."""
    if not line:
        return None
    try:
        entry = json.loads(line)
        return {
            "source_ip":     entry.get("source_ip", "-"),
            "timestamp":     entry.get("timestamp", ""),
            "method":        entry.get("method", "-"),
            "path":          entry.get("path", "-"),
            "status":        int(entry.get("status", 0)),
            "response_size": int(entry.get("response_size", 0)),
        }
    except (json.JSONDecodeError, ValueError):
        return None
