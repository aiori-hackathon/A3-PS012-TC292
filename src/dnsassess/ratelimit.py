from __future__ import annotations

import time
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
    """One global bucket plus one bucket per target.

    ``wait(target_id)`` blocks until a token is available globally and for
    ``target_id``, then consumes one from each.
    """

    rate: RateConfig
    clock: Optional[Callable[[], float]] = None
    sleep: Optional[Callable[[float], None]] = None
    _global: TokenBucket = field(init=False)
    _buckets: dict[str, TokenBucket] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._global = TokenBucket(
            self.rate.global_qps,
            max(1.0, self.rate.global_qps),
            clock=self.clock,
            sleep=self.sleep,
        )

    def _bucket_for(self, target_id: str) -> TokenBucket:
        bucket = self._buckets.get(target_id)
        if bucket is None:
            bucket = TokenBucket(
                self.rate.per_target_qps,
                max(1.0, self.rate.per_target_qps),
                clock=self.clock,
                sleep=self.sleep,
            )
            self._buckets[target_id] = bucket
        return bucket

    def wait(self, target_id: str) -> None:
        """Block until a token is available globally and for ``target_id``."""
        self._global.wait(1.0)
        self._bucket_for(target_id).wait(1.0)
