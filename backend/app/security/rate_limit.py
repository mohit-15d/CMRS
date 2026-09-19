"""Sliding-window rate limiting for login.

Two complementary counters are enforced (both before any credential work):

* **Per-IP request throttle** - limits how many login *attempts* a client IP
  may make in a short window, independent of success/failure.
* **Per-(IP, username) lockout** - after a configurable number of failed
  logins for a specific username from an IP, further attempts are blocked until
  the window elapses. A successful login clears that username's failure count.

All limits and windows are configurable through application settings (see
``app.core.config``) so they come from environment variables, never hard-coded.

The implementation is single-process in-memory and intentional for the current
deployment; a distributed store would be needed behind a load balancer.
"""

import threading
import time
from collections import defaultdict


class RateLimiter:
    """Sliding-window rate limiter using per-key timestamps."""

    def __init__(self) -> None:
        self._window = defaultdict(list)  # key -> [timestamps]
        self._lock = threading.Lock()

    def _purge(self, key: str, window_seconds: float, now: float) -> None:
        cutoff = now - window_seconds
        with self._lock:
            timestamps = self._window[key]
            kept = [t for t in timestamps if t > cutoff]
            if kept:
                self._window[key] = kept
            else:
                self._window.pop(key, None)

    def hit(self, key: str, window_seconds: float, max_hits: int) -> bool:
        """Record a hit; return True if the caller is allowed, False if over limit."""
        now = time.time()
        self._purge(key, window_seconds, now)

        with self._lock:
            hits = self._window.setdefault(key, [])
            if len(hits) >= max_hits:
                return False
            hits.append(now)
            # Trim to the most recent max_hits so memory stays bounded by the limit.
            if len(hits) > max_hits:
                del hits[: len(hits) - max_hits]
            return True

    def clear(self, key: str) -> None:
        """Remove all state for a key (e.g. after a successful login)."""
        with self._lock:
            self._window.pop(key, None)

    def reset(self) -> None:
        """Drop all rate-limit state (used by tests)."""
        with self._lock:
            self._window.clear()


#: Module-level singleton used by the login route.
rate_limiter = RateLimiter()