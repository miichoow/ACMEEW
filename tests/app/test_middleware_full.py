"""Unit tests for acmeeh.app.middleware — TrustedProxyMiddleware and request hooks."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from flask import Flask, g

from acmeeh.app.middleware import TrustedProxyMiddleware, register_request_hooks

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_app(
    settings=None,
    container=None,
    rate_limiter=None,
) -> Flask:
    """Build a minimal Flask app with request hooks registered."""
    app = Flask(__name__)
    app.config["TESTING"] = True

    if settings is not None:
        app.config["ACMEEH_SETTINGS"] = settings
    if container is not None:
        app.extensions["container"] = container
    if rate_limiter is not None:
        app.extensions["rate_limiter"] = rate_limiter

    register_request_hooks(app)

    @app.route("/test")
    def _test_view():
        return {"request_id": g.request_id}

    @app.route("/health")
    def _health():
        return "OK"

    return app


def _make_settings(external_url="https://acme.example.com", hsts_max_age_seconds=63072000):
    return SimpleNamespace(
        server=SimpleNamespace(external_url=external_url),
        security=SimpleNamespace(hsts_max_age_seconds=hsts_max_age_seconds),
        acme=SimpleNamespace(
            paths=SimpleNamespace(
                new_nonce="/acme/new-nonce",
                new_account="/acme/new-account",
                new_order="/acme/new-order",
            ),
        ),
    )


# ═══════════════════════════════════════════════════════════════════════════
# TrustedProxyMiddleware
# ═══════════════════════════════════════════════════════════════════════════


class TestTrustedProxyMiddleware:
    def test_trusted_proxy_sets_remote_addr_from_forwarded_for(self):
        inner_app = MagicMock(return_value=[b"OK"])
        mw = TrustedProxyMiddleware(
            inner_app,
            trusted_proxies=["10.0.0.0/8"],
        )

        environ = {
            "REMOTE_ADDR": "10.0.0.1",
            "HTTP_X_FORWARDED_FOR": "203.0.113.50, 10.0.0.1",
        }
        start_response = MagicMock()

        mw(environ, start_response)

        # Should extract the untrusted client IP
        assert environ["REMOTE_ADDR"] == "203.0.113.50"
        inner_app.assert_called_once_with(environ, start_response)

    def test_untrusted_proxy_passes_through_unchanged(self):
        inner_app = MagicMock(return_value=[b"OK"])
        mw = TrustedProxyMiddleware(
            inner_app,
            trusted_proxies=["10.0.0.0/8"],
        )

        environ = {
            "REMOTE_ADDR": "192.168.1.100",
            "HTTP_X_FORWARDED_FOR": "1.2.3.4",
        }
        start_response = MagicMock()

        mw(environ, start_response)

        # Untrusted proxy: REMOTE_ADDR should NOT change
        assert environ["REMOTE_ADDR"] == "192.168.1.100"

    def test_sets_url_scheme_from_forwarded_proto(self):
        inner_app = MagicMock(return_value=[b"OK"])
        mw = TrustedProxyMiddleware(
            inner_app,
            trusted_proxies=["10.0.0.0/8"],
        )

        environ = {
            "REMOTE_ADDR": "10.0.0.1",
            "HTTP_X_FORWARDED_PROTO": "https",
            "wsgi.url_scheme": "http",
        }
        start_response = MagicMock()

        mw(environ, start_response)

        assert environ["wsgi.url_scheme"] == "https"

    def test_sets_script_name_from_forwarded_prefix(self):
        inner_app = MagicMock(return_value=[b"OK"])
        mw = TrustedProxyMiddleware(
            inner_app,
            trusted_proxies=["10.0.0.0/8"],
        )

        environ = {
            "REMOTE_ADDR": "10.0.0.1",
            "HTTP_X_FORWARDED_PREFIX": "/acme/",
            "SCRIPT_NAME": "",
        }
        start_response = MagicMock()

        mw(environ, start_response)

        # Trailing slash should be stripped
        assert environ["SCRIPT_NAME"] == "/acme"

    def test_parse_networks_with_invalid_entries_logs_warning(self):
        with patch("acmeeh.app.middleware.log") as mock_log:
            mw = TrustedProxyMiddleware(
                MagicMock(),
                trusted_proxies=["10.0.0.0/8", "not-a-network", "192.168.1.0/24"],
            )

        # Should have parsed 2 valid networks
        assert len(mw._networks) == 2
        mock_log.warning.assert_called_once()
        assert "not-a-network" in mock_log.warning.call_args[0][1]

    def test_is_trusted_with_empty_network_list_returns_true(self):
        mw = TrustedProxyMiddleware(MagicMock(), trusted_proxies=[])
        assert mw._is_trusted("192.168.1.1") is True

    def test_is_trusted_with_invalid_addr_returns_false(self):
        mw = TrustedProxyMiddleware(
            MagicMock(),
            trusted_proxies=["10.0.0.0/8"],
        )
        assert mw._is_trusted("not-an-ip") is False

    def test_extract_client_ip_walks_right_to_left(self):
        mw = TrustedProxyMiddleware(
            MagicMock(),
            trusted_proxies=["10.0.0.0/8"],
        )

        # Right-most trusted IPs should be skipped, leftmost untrusted returned
        result = mw._extract_client_ip("203.0.113.50, 10.0.0.2, 10.0.0.1")
        assert result == "203.0.113.50"

    def test_extract_client_ip_all_trusted_returns_leftmost(self):
        mw = TrustedProxyMiddleware(
            MagicMock(),
            trusted_proxies=["10.0.0.0/8"],
        )

        # If all are trusted, returns the first (leftmost)
        result = mw._extract_client_ip("10.0.0.3, 10.0.0.2, 10.0.0.1")
        assert result == "10.0.0.3"


# ═══════════════════════════════════════════════════════════════════════════
# register_request_hooks
# ═══════════════════════════════════════════════════════════════════════════


class TestRegisterRequestHooksBefore:
    def test_before_request_sets_request_id_and_start_time(self):
        app = _make_app()

        with app.test_client() as client:
            resp = client.get("/test")

        data = resp.get_json()
        assert "request_id" in data
        assert len(data["request_id"]) > 0

    def test_before_request_uses_incoming_request_id(self):
        app = _make_app()
        custom_id = "my-custom-request-id-12345"

        with app.test_client() as client:
            resp = client.get("/test", headers={"X-Request-ID": custom_id})

        data = resp.get_json()
        assert data["request_id"] == custom_id


class TestRegisterRequestHooksAfter:
    def test_after_request_adds_security_headers(self):
        app = _make_app()

        with app.test_client() as client:
            resp = client.get("/health")

        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert "default-src 'none'" in resp.headers["Content-Security-Policy"]

    def test_after_request_adds_hsts_for_https(self):
        settings = _make_settings(
            external_url="https://acme.example.com",
            hsts_max_age_seconds=31536000,
        )
        app = _make_app(settings=settings)

        with app.test_client() as client:
            resp = client.get("/health")

        assert "Strict-Transport-Security" in resp.headers
        assert "max-age=31536000" in resp.headers["Strict-Transport-Security"]
        assert "includeSubDomains" in resp.headers["Strict-Transport-Security"]

    def test_after_request_no_hsts_for_http(self):
        settings = _make_settings(
            external_url="http://acme.example.com",
            hsts_max_age_seconds=31536000,
        )
        app = _make_app(settings=settings)

        with app.test_client() as client:
            resp = client.get("/health")

        assert "Strict-Transport-Security" not in resp.headers

    def test_after_request_no_hsts_when_max_age_zero(self):
        settings = _make_settings(
            external_url="https://acme.example.com",
            hsts_max_age_seconds=0,
        )
        app = _make_app(settings=settings)

        with app.test_client() as client:
            resp = client.get("/health")

        assert "Strict-Transport-Security" not in resp.headers

    def test_after_request_attaches_request_id(self):
        app = _make_app()

        with app.test_client() as client:
            resp = client.get("/health")

        assert "X-Request-ID" in resp.headers
        assert len(resp.headers["X-Request-ID"]) > 0

    def test_after_request_passes_through_custom_request_id(self):
        app = _make_app()
        custom_id = "trace-abc-123"

        with app.test_client() as client:
            resp = client.get("/health", headers={"X-Request-ID": custom_id})

        assert resp.headers["X-Request-ID"] == custom_id

    def test_after_request_without_settings_no_hsts(self):
        """When ACMEEH_SETTINGS is not set, HSTS should not be added."""
        app = _make_app(settings=None)

        with app.test_client() as client:
            resp = client.get("/health")

        assert "Strict-Transport-Security" not in resp.headers
        # Security headers should still be present
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
