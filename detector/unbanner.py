"""
Background thread that checks for expired bans every 30 seconds.
"""
import threading
import time

from blocker import check_unbans


def start_unbanner():
    def _loop():
        while True:
            try:
                check_unbans()
            except Exception as e:
                print(f"[unbanner] error: {e}")
            time.sleep(30)

    t = threading.Thread(target=_loop, daemon=True, name="unbanner")
    t.start()
    return t
