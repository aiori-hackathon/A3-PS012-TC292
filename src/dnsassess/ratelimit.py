from __future__ import annotations

import time
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

from .config import RateConfig


class TokenBucket:
    """A single token bucket refilling at ``rate_per_second`` tokens/s."""

    def __init__(
        self,
        rate_per_second: float,
        capacity: float,
        clock: Optional[Callable[[], float]] = None,
        sleep: Optional[Callable[[float], None]] = None,
    ) -> None:
        self.rate = rate_per_second
        self.capacity = float(capacity)
        self.clock = clock or time.monotonic
        self.sleep = sleep or time.sleep
        self._tokens = float(capacity)
        self._last = self.clock()

    def _refill(self) -> None:
        now = self.clock()
        elapsed = max(0.0, now - self._last)
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last = now

    def wait(self, tokens: float = 1.0) -> None:
        """Block until ``tokens`` are available, then consume them."""
        while True:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return
            deficit = tokens - self._tokens
            self.sleep(deficit / self.rate)


@dataclass
class RateLimiter:
    """Schedule queries against global and per-target minimum intervals.

    ``wait(target_id)`` blocks until both configured query-rate intervals
    have elapsed. A small scheduling margin prevents clock and send overhead
    from pushing observed rates over their configured caps.
    """

    rate: RateConfig
    clock: Optional[Callable[[], float]] = None
    sleep: Optional[Callable[[float], None]] = None
    _global_next: float = field(init=False)
    _target_next: dict[str, float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def __post_init__(self) -> None:
        self._global_next = (self.clock or time.monotonic)()

    def wait(self, target_id: str) -> None:
        """Block until global and per-target request intervals are satisfied."""
        clock = self.clock or time.monotonic
        sleep = self.sleep or time.sleep
        margin = 0.01
        with self._lock:
            now = clock()
            scheduled = max(
                now,
                self._global_next,
                self._target_next.get(target_id, now),
            )
            if scheduled > now:
                sleep(scheduled - now)
            sent_at = clock()
            self._global_next = sent_at + 1.0 / self.rate.global_qps + margin
            self._target_next[target_id] = (
                sent_at + 1.0 / self.rate.per_target_qps + margin
            )
