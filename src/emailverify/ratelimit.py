"""A token-bucket rate limiter.

Verimail does not document a rate limit, which is exactly why we impose one of
our own: an undocumented limit is still a limit, and discovering it by getting
throttled mid-run is worse than pacing ourselves.
"""

from __future__ import annotations

import threading
import time


class TokenBucket:
    """Thread-safe token bucket. `acquire()` blocks until a token is free."""

    def __init__(self, rate_per_second: float, burst: float | None = None) -> None:
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be > 0")
        self.rate = float(rate_per_second)
        self.capacity = float(burst) if burst is not None else max(1.0, float(rate_per_second))
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0) -> float:
        """Consume `tokens`, sleeping if necessary. Returns seconds slept."""
        slept = 0.0
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._updated) * self.rate
                )
                self._updated = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return slept
                deficit = tokens - self._tokens
                wait = deficit / self.rate
            # Sleep outside the lock so other threads can keep accounting.
            time.sleep(wait)
            slept += wait
