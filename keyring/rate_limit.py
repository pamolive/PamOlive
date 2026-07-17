import math
import threading
import time
from collections import defaultdict, deque


class SlidingWindowRateLimiter:
    """Thread-safe, bounded sliding-window limiter for internal key operations."""

    def __init__(self, limits, *, window_seconds=60, clock=None):
        self.limits = dict(limits)
        self.window_seconds = window_seconds
        self.clock = clock or time.monotonic
        self._events = defaultdict(deque)
        self._lock = threading.Lock()

    def acquire(self, operation):
        limit = self.limits.get(operation, self.limits["default"])
        now = self.clock()
        cutoff = now - self.window_seconds
        with self._lock:
            events = self._events[operation]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                retry_after = max(1, math.ceil(events[0] + self.window_seconds - now))
                return False, retry_after
            events.append(now)
        return True, 0
