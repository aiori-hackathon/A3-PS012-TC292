from dnsassess.config import RateConfig
from dnsassess.ratelimit import RateLimiter, TokenBucket


class FakeClock:
    def __init__(self, start: float = 0.0):
        self.value = start

    def __call__(self) -> float:
        return self.value


def test_bucket_consumes_available_token_without_sleeping():
    clock = FakeClock(0.0)
    sleeps: list[float] = []

    def fake_sleep(dt: float) -> None:
        sleeps.append(dt)
        clock.value += dt

    bucket = TokenBucket(rate_per_second=1.0, capacity=1.0, clock=clock, sleep=fake_sleep)
    bucket.wait(1.0)
    assert sleeps == []


def test_bucket_blocks_until_token_refills():
    clock = FakeClock(0.0)
    sleeps: list[float] = []

    def fake_sleep(dt: float) -> None:
        sleeps.append(dt)
        clock.value += dt

    bucket = TokenBucket(rate_per_second=1.0, capacity=1.0, clock=clock, sleep=fake_sleep)
    bucket.wait(1.0)  # consume the single token
    bucket.wait(1.0)  # must wait ~1s for refill
    assert sleeps == [1.0]


def test_rate_limiter_global_and_per_target_buckets():
    clock = FakeClock(0.0)
    sleeps: list[float] = []

    def fake_sleep(dt: float) -> None:
        sleeps.append(dt)
        clock.value += dt

    rate = RateConfig(
        global_qps=1.0,
        per_target_qps=1.0,
        max_queries_per_target=3,
        timeout_seconds=2.0,
        max_total_queries=80,
        edns_payload=1232,
    )
    limiter = RateLimiter(rate=rate, clock=clock, sleep=fake_sleep)

    limiter.wait("t01")  # both buckets have a token
    limiter.wait("t01")  # both empty → one refill sleep covers both
    assert sleeps == [1.0]


def test_per_target_buckets_are_independent():
    clock = FakeClock(0.0)
    sleeps: list[float] = []

    def fake_sleep(dt: float) -> None:
        sleeps.append(dt)
        clock.value += dt

    rate = RateConfig(
        global_qps=100.0,
        per_target_qps=1.0,
        max_queries_per_target=3,
        timeout_seconds=2.0,
        max_total_queries=80,
        edns_payload=1232,
    )
    limiter = RateLimiter(rate=rate, clock=clock, sleep=fake_sleep)

    limiter.wait("t01")
    limiter.wait("t02")  # separate per-target bucket, no sleep needed
    assert sleeps == []
