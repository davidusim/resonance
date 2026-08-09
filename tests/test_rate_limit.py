from resonance.rate_limit import TokenBucketRateLimiter


def test_token_bucket_blocks_until_a_token_refills() -> None:
    now = [100.0]
    limiter = TokenBucketRateLimiter(
        2,
        window_seconds=60,
        clock=lambda: now[0],
    )

    assert limiter.check("client").allowed
    assert limiter.check("client").allowed
    blocked = limiter.check("client")

    assert not blocked.allowed
    assert blocked.retry_after_seconds == 30

    now[0] += 30
    assert limiter.check("client").allowed


def test_token_bucket_evicts_least_recent_client_at_capacity() -> None:
    limiter = TokenBucketRateLimiter(1, max_clients=2, clock=lambda: 100.0)

    assert limiter.check("oldest").allowed
    assert limiter.check("newer").allowed
    assert limiter.check("newest").allowed

    assert limiter.tracked_clients == 2
    assert limiter.check("oldest").allowed
    assert limiter.tracked_clients == 2
