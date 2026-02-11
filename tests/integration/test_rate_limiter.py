"""Integration tests for rate limiting."""

import pytest

from acmeeh.app.errors import AcmeProblem
from acmeeh.app.rate_limiter import RateLimiter
from acmeeh.config.settings import RateLimitRule, RateLimitSettings


def test_rate_limiter_allows_under_limit():
    """Requests under the limit should pass."""
    settings = RateLimitSettings(
        enabled=True,
        backend="memory",
        new_account=RateLimitRule(requests=5, window_seconds=60),
        new_order=RateLimitRule(requests=10, window_seconds=60),
        new_order_per_identifier=RateLimitRule(requests=50, window_seconds=604800),
        new_nonce=RateLimitRule(requests=100, window_seconds=60),
        challenge=RateLimitRule(requests=10, window_seconds=60),
        challenge_validation=RateLimitRule(requests=30, window_seconds=60),
        gc_interval_seconds=300,
        gc_max_age_seconds=7200,
    )
    limiter = RateLimiter(settings)

    # Should not raise
    for _ in range(5):
        limiter.check("192.168.1.1", "new_account")


def test_rate_limiter_blocks_over_limit():
    """Requests over the limit should raise AcmeProblem."""
    settings = RateLimitSettings(
        enabled=True,
        backend="memory",
        new_account=RateLimitRule(requests=3, window_seconds=60),
        new_order=RateLimitRule(requests=10, window_seconds=60),
        new_order_per_identifier=RateLimitRule(requests=50, window_seconds=604800),
        new_nonce=RateLimitRule(requests=100, window_seconds=60),
        challenge=RateLimitRule(requests=10, window_seconds=60),
        challenge_validation=RateLimitRule(requests=30, window_seconds=60),
        gc_interval_seconds=300,
        gc_max_age_seconds=7200,
    )
    limiter = RateLimiter(settings)

    for _ in range(3):
        limiter.check("192.168.1.1", "new_account")

    with pytest.raises(AcmeProblem) as exc_info:
        limiter.check("192.168.1.1", "new_account")

    assert exc_info.value.status == 429
    assert "Retry-After" in exc_info.value.extra_headers


def test_rate_limiter_disabled():
    """Disabled rate limiter should not block anything."""
    settings = RateLimitSettings(
        enabled=False,
        backend="memory",
        new_account=RateLimitRule(requests=1, window_seconds=60),
        new_order=RateLimitRule(requests=1, window_seconds=60),
        new_order_per_identifier=RateLimitRule(requests=50, window_seconds=604800),
        new_nonce=RateLimitRule(requests=100, window_seconds=60),
        challenge=RateLimitRule(requests=1, window_seconds=60),
        challenge_validation=RateLimitRule(requests=30, window_seconds=60),
        gc_interval_seconds=300,
        gc_max_age_seconds=7200,
    )
    limiter = RateLimiter(settings)

    # Should not raise even over limit
    for _ in range(100):
        limiter.check("192.168.1.1", "new_account")


def test_rate_limiter_different_ips():
    """Different IPs should have separate counters."""
    settings = RateLimitSettings(
        enabled=True,
        backend="memory",
        new_account=RateLimitRule(requests=2, window_seconds=60),
        new_order=RateLimitRule(requests=10, window_seconds=60),
        new_order_per_identifier=RateLimitRule(requests=50, window_seconds=604800),
        new_nonce=RateLimitRule(requests=100, window_seconds=60),
        challenge=RateLimitRule(requests=10, window_seconds=60),
        challenge_validation=RateLimitRule(requests=30, window_seconds=60),
        gc_interval_seconds=300,
        gc_max_age_seconds=7200,
    )
    limiter = RateLimiter(settings)

    limiter.check("10.0.0.1", "new_account")
    limiter.check("10.0.0.1", "new_account")
    # IP1 is at limit

    # IP2 should still work
    limiter.check("10.0.0.2", "new_account")
    limiter.check("10.0.0.2", "new_account")
