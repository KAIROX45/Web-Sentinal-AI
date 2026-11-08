import time
import asyncio
from collections import defaultdict
from typing import Dict, List, Tuple
from app.config import settings


class SlidingWindowRateLimiter:
    """
    In-memory sliding window rate limiter to throttle request volume
    and protect downstream AI/threat-intelligence quotas and backend resources.
    """
    def __init__(self, limit_per_minute: int = 60, window_seconds: float = 60.0):
        self.limit = limit_per_minute
        self.window = window_seconds
        self._records: Dict[str, List[float]] = defaultdict(list)
        self._lock = asyncio.Lock()
        self._sweep_counter = 0

    async def acquire(self, key: str) -> Tuple[bool, int]:
        """
        Attempts to acquire a rate limit slot for the given key (IP address).
        Returns:
            Tuple[bool, int]: (is_allowed, retry_after_seconds)
        """
        async with self._lock:
            now = time.time()
            cutoff = now - self.window
            
            # Filter timestamps to keep only those within current window
            valid_timestamps = [t for t in self._records[key] if t > cutoff]
            
            if len(valid_timestamps) >= self.limit:
                # Exceeded: calculate wait time based on oldest timestamp in window
                oldest_in_window = valid_timestamps[0]
                retry_after = max(1, int(self.window - (now - oldest_in_window)) + 1)
                self._records[key] = valid_timestamps
                return False, retry_after
            
            # Allowed: register current request timestamp
            valid_timestamps.append(now)
            self._records[key] = valid_timestamps
            
            # Periodic cleanup of stale keys
            self._sweep_counter += 1
            if self._sweep_counter >= 100:
                self._sweep_counter = 0
                stale_keys = [k for k, timestamps in self._records.items() if not timestamps or timestamps[-1] <= cutoff]
                for k in stale_keys:
                    self._records.pop(k, None)
                    
            return True, 0

    async def reset(self) -> None:
        """Resets all tracked rate limiting states (useful for test suites)."""
        async with self._lock:
            self._records.clear()
            self._sweep_counter = 0


rate_limiter = SlidingWindowRateLimiter(
    limit_per_minute=settings.RATE_LIMIT_PER_MINUTE,
    window_seconds=60.0
)

