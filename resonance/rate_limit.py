"""Small, memory-bounded token-bucket rate limiter for a single-process deployment."""

from __future__ import annotations

import math
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int = 0


@dataclass
class _Bucket:
    tokens: float
    updated_at: float


class TokenBucketRateLimiter:
    """Limit attempts per client while capping the number of retained client keys."""

    def __init__(
        self,
        attempts: int,
        *,
        window_seconds: int = 60,
        max_clients: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if attempts < 1 or window_seconds < 1 or max_clients < 1:
            raise ValueError("Rate-limit settings must be positive integers")
        self._capacity = float(attempts)
        self._refill_per_second = attempts / window_seconds
        self._max_clients = max_clients
        self._clock = clock
        self._buckets: OrderedDict[str, _Bucket] = OrderedDict()
        self._lock = threading.Lock()

    def check(self, client_key: str) -> RateLimitDecision:
        now = self._clock()
        with self._lock:
            bucket = self._buckets.pop(client_key, None)
            if bucket is None:
                if len(self._buckets) >= self._max_clients:
                    self._buckets.popitem(last=False)
                bucket = _Bucket(tokens=self._capacity, updated_at=now)
            else:
                elapsed = max(0.0, now - bucket.updated_at)
                bucket.tokens = min(
                    self._capacity,
                    bucket.tokens + elapsed * self._refill_per_second,
                )
                bucket.updated_at = now

            if bucket.tokens >= 1:
                bucket.tokens -= 1
                decision = RateLimitDecision(allowed=True)
            else:
                retry_after = math.ceil((1 - bucket.tokens) / self._refill_per_second)
                decision = RateLimitDecision(
                    allowed=False,
                    retry_after_seconds=max(1, retry_after),
                )
            self._buckets[client_key] = bucket
            return decision

    @property
    def tracked_clients(self) -> int:
        with self._lock:
            return len(self._buckets)
