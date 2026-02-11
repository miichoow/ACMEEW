"""Tests covering untested lines in rate_limiter.py and middleware.py."""

import time
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from flask import Flask, g

from acmeeh.app.middleware import register_request_hooks
from acmeeh.app.rate_limiter import DatabaseRateLimiter, InMemoryRateLimiter, create_rate_limiter

# ---------------------------------------------------------------------------
# Fake settings helpers
# ---------------------------------------------------------------------------


class FakeRule:
    def __init__(self, requests=5, window_seconds=60):
        self.requests = requests
        self.window_seconds = window_seconds


class FakeSettings:
    def __init__(
        self,
        enabled=True,
        gc_interval_seconds=300,
        gc_max_age_seconds=3600,
        backend="memory",
    ):
        self.enabled = enabled
        self.gc_interval_seconds = gc_interval_seconds
        self.gc_max_age_seconds = gc_max_age_seconds
        self.backend = backend
        self.new_nonce = FakeRule()
        self.new_account = FakeRule()
        self.new_order = FakeRule()
        self.challenge = FakeRule()


# ===================================================================
# Rate Limiter Tests
# ===================================================================


class TestInMemoryRateLimiterUnknownCategory:
    """check() with an unknown category returns immediately (line 41)."""

    def test_unknown_category_returns_none(self):
        settings = FakeSettings(enabled=True)
        limiter = InMemoryRateLimiter(settings)
        result = limiter.check("192.168.1.1", "unknown_category")
        assert result is None

    def test_unknown_category_does_not_create_window(self):
        settings = FakeSettings(enabled=True)
        limiter = InMemoryRateLimiter(settings)
        limiter.check("192.168.1.1", "totally_bogus")
        assert "totally_bogus" not in limiter._windows


class TestInMemoryRateLimiterDisabled:
    """check() with enabled=False returns immediately."""

    def test_disabled_returns_none(self):
        settings = FakeSettings(enabled=False)
        limiter = InMemoryRateLimiter(settings)
        result = limiter.check("192.168.1.1", "new_nonce")
        assert result is None

    def test_disabled_does_not_record(self):
        settings = FakeSettings(enabled=False)
        limiter = InMemoryRateLimiter(settings)
        limiter.check("192.168.1.1", "new_nonce")
        assert len(limiter._windows) == 0


class TestInMemoryMaybeCleanup:
    """Trigger _maybe_cleanup by making _last_cleanup very old (lines 77-89)."""

    def test_old_entries_pruned(self):
        settings = FakeSettings(enabled=True, gc_interval_seconds=10)
        settings.new_nonce = FakeRule(requests=100, window_seconds=60)
        limiter = InMemoryRateLimiter(settings)

        now = time.monotonic()

        # Pre-populate _windows with old timestamps (well outside the window)
        limiter._windows["new_nonce"] = {
            "old_ip": [now - 200, now - 180, now - 170],
            "recent_ip": [now - 5, now - 2],
        }

        # Make _last_cleanup very old so cleanup triggers on next check
        limiter._last_cleanup = now - 1000

        # This check call should trigger _maybe_cleanup internally
        limiter.check("trigger_ip", "new_nonce")

        # Old entries should be pruned entirely (all timestamps > 60s old)
        assert "old_ip" not in limiter._windows.get("new_nonce", {}), (
            "Bucket with only old timestamps should be deleted"
        )

        # Recent entries should survive
        assert "recent_ip" in limiter._windows.get("new_nonce", {}), (
            "Bucket with recent timestamps should survive cleanup"
        )

    def test_empty_buckets_deleted(self):
        settings = FakeSettings(enabled=True, gc_interval_seconds=1)
        settings.new_account = FakeRule(requests=100, window_seconds=10)
        limiter = InMemoryRateLimiter(settings)

        now = time.monotonic()

        # All timestamps are old — the entire bucket should be removed
        limiter._windows["new_account"] = {
            "ip1": [now - 500],
            "ip2": [now - 400],
        }
        limiter._last_cleanup = now - 100

        limiter.check("fresh_ip", "new_account")

        # Both sub-buckets had only expired entries
        bucket = limiter._windows.get("new_account", {})
        assert "ip1" not in bucket
        assert "ip2" not in bucket

    def test_cleanup_skipped_when_interval_not_elapsed(self):
        settings = FakeSettings(enabled=True, gc_interval_seconds=9999)
        settings.new_nonce = FakeRule(requests=100, window_seconds=60)
        limiter = InMemoryRateLimiter(settings)

        now = time.monotonic()
        limiter._last_cleanup = now  # Just cleaned up

        # Put old data in — should NOT be cleaned because interval hasn't elapsed
        limiter._windows["new_nonce"] = {
            "stale_ip": [now - 500],
        }

        limiter.check("trigger_ip", "new_nonce")

        # Stale data still present because cleanup was skipped
        assert "stale_ip" in limiter._windows.get("new_nonce", {})


class TestInMemoryMaybeCleanupSkipsUnknownRules:
    """Category exists in _windows but not in settings — rule is None, continue."""

    def test_unknown_rule_category_skipped(self):
        settings = FakeSettings(enabled=True, gc_interval_seconds=1)
        settings.new_nonce = FakeRule(requests=100, window_seconds=60)
        limiter = InMemoryRateLimiter(settings)

        now = time.monotonic()
        limiter._last_cleanup = now - 100  # Force cleanup

        # Manually insert a category that has no matching settings attribute
        limiter._windows["nonexistent_category"] = {
            "some_ip": [now - 10],
        }
        # Also add a valid category with old data
        limiter._windows["new_nonce"] = {
            "old_ip": [now - 500],
        }

        limiter.check("trigger_ip", "new_nonce")

        # The unknown category should still exist (skipped with continue)
        assert "nonexistent_category" in limiter._windows
        assert "some_ip" in limiter._windows["nonexistent_category"]

        # The valid category's old entry should be cleaned
        assert "old_ip" not in limiter._windows.get("new_nonce", {})


class TestDatabaseRateLimiterDisabled:
    """check() with enabled=False returns immediately (line 105)."""

    def test_disabled_returns_none(self):
        settings = FakeSettings(enabled=False)
        mock_db = MagicMock()
        limiter = DatabaseRateLimiter(settings, mock_db)
        result = limiter.check("192.168.1.1", "new_nonce")
        assert result is None
        mock_db.execute.assert_not_called()


class TestDatabaseRateLimiterUnknownCategory:
    """Unknown category returns immediately (line 109)."""

    def test_unknown_category_returns_none(self):
        settings = FakeSettings(enabled=True)
        mock_db = MagicMock()
        limiter = DatabaseRateLimiter(settings, mock_db)
        result = limiter.check("192.168.1.1", "unknown_category")
        assert result is None
        mock_db.execute.assert_not_called()


class TestDatabaseRateLimiterGc:
    """gc() with default and explicit max_age (lines 148-153)."""

    def test_gc_default_max_age(self):
        settings = FakeSettings(enabled=True, gc_max_age_seconds=7200)
        mock_db = MagicMock()
        limiter = DatabaseRateLimiter(settings, mock_db)

        limiter.gc()

        mock_db.execute.assert_called_once()
        call_args = mock_db.execute.call_args
        sql = call_args[0][0]
        assert "DELETE FROM rate_limit_counters" in sql
        assert "window_start" in sql

        # The cutoff should be roughly now - 7200 seconds
        cutoff = call_args[0][1][0]
        assert isinstance(cutoff, datetime)
        assert cutoff.tzinfo is not None

    def test_gc_explicit_max_age(self):
        settings = FakeSettings(enabled=True, gc_max_age_seconds=7200)
        mock_db = MagicMock()
        limiter = DatabaseRateLimiter(settings, mock_db)

        limiter.gc(max_age_seconds=1800)

        mock_db.execute.assert_called_once()
        call_args = mock_db.execute.call_args
        cutoff = call_args[0][1][0]
        assert isinstance(cutoff, datetime)
        # With explicit 1800s, the cutoff should be more recent than the default 7200s
        expected_approx = datetime.fromtimestamp(time.time() - 1800, tz=UTC)
        # Allow 5 seconds of drift
        diff = abs((cutoff - expected_approx).total_seconds())
        assert diff < 5, f"Cutoff drift too large: {diff}s"


class TestCreateRateLimiter:
    """Factory function create_rate_limiter with different backends."""

    def test_memory_backend(self):
        settings = FakeSettings(enabled=True, backend="memory")
        limiter = create_rate_limiter(settings)
        assert isinstance(limiter, InMemoryRateLimiter)

    def test_database_backend(self):
        settings = FakeSettings(enabled=True, backend="database")
        mock_db = MagicMock()
        limiter = create_rate_limiter(settings, db=mock_db)
        assert isinstance(limiter, DatabaseRateLimiter)

    def test_memory_backend_no_db_required(self):
        settings = FakeSettings(enabled=True, backend="memory")
        limiter = create_rate_limiter(settings, db=None)
        assert isinstance(limiter, InMemoryRateLimiter)


# ===================================================================
# Middleware Tests
# ===================================================================


@pytest.fixture()
def rate_app():
    """Flask test app with rate limiter and settings wired up."""
    app = Flask("test_middleware")
    app.config["TESTING"] = True

    mock_limiter = MagicMock()
    app.extensions["rate_limiter"] = mock_limiter

    settings = MagicMock()
    settings.acme.paths.new_nonce = "/new-nonce"
    settings.acme.paths.new_account = "/new-account"
    settings.acme.paths.new_order = "/new-order"
    settings.server.external_url = "http://localhost"
    settings.security.hsts_max_age_seconds = 0

    app.config["ACMEEH_SETTINGS"] = settings

    register_request_hooks(app)

    @app.route("/acme/new-nonce")
    def nonce_route():
        return "ok"

    @app.route("/acme/new-account", methods=["GET", "POST"])
    def account_route():
        return "ok"

    @app.route("/acme/new-order", methods=["GET", "POST"])
    def order_route():
        return "ok"

    @app.route("/chall/test-token")
    def chall_route():
        return "ok"

    @app.route("/other")
    def other_route():
        return "ok"

    return app, mock_limiter


class TestMiddlewareRateLimitNewNonce:
    """Request to path ending with '/new-nonce' calls check with 'new_nonce'."""

    def test_new_nonce_category(self, rate_app):
        app, limiter = rate_app
        with app.test_client() as client:
            client.get("/acme/new-nonce")

        limiter.check.assert_called_once()
        args = limiter.check.call_args
        assert args[0][1] == "new_nonce"


class TestMiddlewareRateLimitNewAccount:
    """Request to path ending with '/new-account' calls check with 'new_account'."""

    def test_new_account_category(self, rate_app):
        app, limiter = rate_app
        with app.test_client() as client:
            client.post("/acme/new-account")

        limiter.check.assert_called_once()
        args = limiter.check.call_args
        assert args[0][1] == "new_account"


class TestMiddlewareRateLimitNewOrder:
    """Request to path ending with '/new-order' calls check with 'new_order'."""

    def test_new_order_category(self, rate_app):
        app, limiter = rate_app
        with app.test_client() as client:
            client.post("/acme/new-order")

        limiter.check.assert_called_once()
        args = limiter.check.call_args
        assert args[0][1] == "new_order"


class TestMiddlewareRateLimitChallenge:
    """Request to path containing '/chall/' calls check with 'challenge'."""

    def test_challenge_category(self, rate_app):
        app, limiter = rate_app
        with app.test_client() as client:
            client.get("/chall/test-token")

        limiter.check.assert_called_once()
        args = limiter.check.call_args
        assert args[0][1] == "challenge"


class TestMiddlewareRateLimitNoCategory:
    """Path that doesn't match any category does NOT call rate_limiter.check."""

    def test_no_category_no_check(self, rate_app):
        app, limiter = rate_app
        with app.test_client() as client:
            client.get("/other")

        limiter.check.assert_not_called()


class TestMiddlewareRateLimitNoSettings:
    """rate_limiter exists but ACMEEH_SETTINGS is None -> no error."""

    def test_no_settings_no_error(self):
        app = Flask("test_no_settings")
        app.config["TESTING"] = True

        mock_limiter = MagicMock()
        app.extensions["rate_limiter"] = mock_limiter
        app.config["ACMEEH_SETTINGS"] = None

        register_request_hooks(app)

        @app.route("/acme/new-nonce")
        def nonce_route():
            return "ok"

        with app.test_client() as client:
            resp = client.get("/acme/new-nonce")

        assert resp.status_code == 200
        mock_limiter.check.assert_not_called()


class TestMiddlewareMetricsIncrement:
    """container.metrics_collector exists -> increment called."""

    def test_metrics_increment_called(self):
        app = Flask("test_metrics")
        app.config["TESTING"] = True

        mock_collector = MagicMock()
        mock_container = MagicMock()
        mock_container.metrics_collector = mock_collector

        app.extensions["container"] = mock_container

        settings = MagicMock()
        settings.server.external_url = "http://localhost"
        settings.security.hsts_max_age_seconds = 0
        app.config["ACMEEH_SETTINGS"] = settings

        register_request_hooks(app)

        @app.route("/test-metrics")
        def metrics_route():
            return "ok"

        with app.test_client() as client:
            resp = client.get("/test-metrics")

        assert resp.status_code == 200
        mock_collector.increment.assert_called_once()


class TestElapsedMsNoStartTime:
    """Request without g.start_time -> _elapsed_ms returns 0.0 (line 221)."""

    def test_elapsed_ms_returns_zero(self):
        from acmeeh.app.middleware import _elapsed_ms

        app = Flask("test_elapsed")
        app.config["TESTING"] = True

        with app.test_request_context("/"):
            # Do NOT set g.start_time
            result = _elapsed_ms()
            assert result == 0.0

    def test_elapsed_ms_with_start_time(self):
        from acmeeh.app.middleware import _elapsed_ms

        app = Flask("test_elapsed2")
        app.config["TESTING"] = True

        with app.test_request_context("/"):
            g.start_time = time.monotonic() - 0.1  # 100ms ago
            result = _elapsed_ms()
            assert result > 50.0  # Should be roughly 100ms
            assert result < 500.0  # But not wildly off


class TestMiddlewareClientIpPassedToCheck:
    """Verify that client IP is passed as the first argument to check."""

    def test_client_ip_is_first_arg(self, rate_app):
        app, limiter = rate_app
        with app.test_client() as client:
            client.get("/acme/new-nonce")

        limiter.check.assert_called_once()
        args = limiter.check.call_args[0]
        # First arg is the client IP (127.0.0.1 for test client)
        assert args[0] in ("127.0.0.1", "unknown")
        assert args[1] == "new_nonce"
