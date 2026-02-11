"""Tests for the acmeeh.logging module — sanitize, setup, and audit_cleanup."""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from acmeeh.logging.audit_cleanup import cleanup_old_audit_logs
from acmeeh.logging.sanitize import (
    sanitize_for_logs,
    sanitize_jwk,
    sanitize_pem,
)
from acmeeh.logging.setup import (
    RequestContextFilter,
    StructuredFormatter,
    TextFormatter,
    configure_logging,
)

# ===========================================================================
# sanitize.py
# ===========================================================================


class TestSanitizeJwk:
    """Tests for sanitize_jwk."""

    def test_redacts_key_material(self):
        """Key material fields are replaced with [REDACTED]."""
        jwk = {
            "kty": "RSA",
            "n": "modulus-data",
            "e": "exponent-data",
            "d": "private-exponent",
            "alg": "RS256",
            "kid": "key-id-123",
        }
        result = sanitize_jwk(jwk)

        assert result["n"] == "[REDACTED]"
        assert result["e"] == "[REDACTED]"
        assert result["d"] == "[REDACTED]"

    def test_preserves_metadata(self):
        """Non-secret metadata fields are preserved."""
        jwk = {
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "alg": "ES256",
            "kid": "my-key-id",
            "key_ops": ["sign"],
            "x": "x-coordinate",
            "y": "y-coordinate",
        }
        result = sanitize_jwk(jwk)

        assert result["kty"] == "EC"
        assert result["crv"] == "P-256"
        assert result["use"] == "sig"
        assert result["alg"] == "ES256"
        assert result["kid"] == "my-key-id"
        assert result["key_ops"] == ["sign"]
        assert result["x"] == "[REDACTED]"
        assert result["y"] == "[REDACTED]"

    def test_empty_jwk(self):
        """Empty dict returns empty dict."""
        assert sanitize_jwk({}) == {}


class TestSanitizePem:
    """Tests for sanitize_pem."""

    def test_redacts_base64_body(self):
        """Base64 body between markers is replaced with [REDACTED]."""
        pem = (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIBkTCB+wIJALRiMLAh0EHJMA0GCSqGSIb3DQEBCwUA\n"
            "MBExDzANBgNVBAMMBnJvb3RjYTAeFw0yNDAxMDEwMDAw\n"
            "-----END CERTIFICATE-----\n"
        )
        result = sanitize_pem(pem)

        assert "-----BEGIN CERTIFICATE-----" in result
        assert "-----END CERTIFICATE-----" in result
        assert "[REDACTED]" in result
        assert "MIIBkTCB" not in result

    def test_preserves_markers(self):
        """BEGIN and END markers are preserved for type identification."""
        pem = "-----BEGIN RSA PRIVATE KEY-----\nbase64data\n-----END RSA PRIVATE KEY-----\n"
        result = sanitize_pem(pem)

        assert "-----BEGIN RSA PRIVATE KEY-----" in result
        assert "-----END RSA PRIVATE KEY-----" in result

    def test_multiple_pem_blocks(self):
        """Multiple PEM blocks are all redacted."""
        pem = (
            "-----BEGIN CERTIFICATE-----\n"
            "cert1data\n"
            "-----END CERTIFICATE-----\n"
            "-----BEGIN CERTIFICATE-----\n"
            "cert2data\n"
            "-----END CERTIFICATE-----\n"
        )
        result = sanitize_pem(pem)

        assert result.count("[REDACTED]") == 2
        assert "cert1data" not in result
        assert "cert2data" not in result

    def test_non_pem_string_passthrough(self):
        """String without PEM markers passes through unchanged."""
        text = "This is not a PEM string."
        assert sanitize_pem(text) == text


class TestSanitizeForLogs:
    """Tests for sanitize_for_logs."""

    def test_dict_with_kty_triggers_jwk_sanitization(self):
        """Dict containing 'kty' is treated as JWK."""
        data = {"kty": "EC", "x": "secret-x", "crv": "P-256"}
        result = sanitize_for_logs(data)

        assert result["kty"] == "EC"
        assert result["crv"] == "P-256"
        assert result["x"] == "[REDACTED]"

    def test_list_recursion(self):
        """Lists are recursed into."""
        data = [
            {"kty": "EC", "x": "secret-x"},
            "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
        ]
        result = sanitize_for_logs(data)

        assert isinstance(result, list)
        assert result[0]["x"] == "[REDACTED]"
        assert "[REDACTED]" in result[1]

    def test_tuple_recursion(self):
        """Tuples are recursed into and returned as tuples."""
        data = (
            {"kty": "RSA", "n": "secret"},
            "plain text",
        )
        result = sanitize_for_logs(data)

        assert isinstance(result, tuple)
        assert result[0]["n"] == "[REDACTED]"
        assert result[1] == "plain text"

    def test_pem_string(self):
        """String containing PEM markers is sanitized."""
        pem = "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"
        result = sanitize_for_logs(pem)

        assert "[REDACTED]" in result
        assert "secret" not in result

    def test_non_sensitive_data_passthrough(self):
        """Non-sensitive data types pass through unchanged."""
        assert sanitize_for_logs(42) == 42
        assert sanitize_for_logs(3.14) == 3.14
        assert sanitize_for_logs(None) is None
        assert sanitize_for_logs(True) is True
        assert sanitize_for_logs("hello world") == "hello world"

    def test_nested_dict_without_kty(self):
        """Dict without 'kty' has its values recursively sanitized."""
        data = {
            "header": {"alg": "ES256"},
            "key": "-----BEGIN EC PRIVATE KEY-----\nsecret\n-----END EC PRIVATE KEY-----",
        }
        result = sanitize_for_logs(data)

        assert result["header"]["alg"] == "ES256"
        assert "[REDACTED]" in result["key"]


# ===========================================================================
# setup.py — StructuredFormatter
# ===========================================================================


class TestStructuredFormatter:
    """Tests for StructuredFormatter."""

    def _make_record(self, msg: str = "Test message", **extra) -> logging.LogRecord:
        """Create a LogRecord for testing."""
        record = logging.LogRecord(
            name="acmeeh.test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg=msg,
            args=(),
            exc_info=None,
        )
        for key, value in extra.items():
            setattr(record, key, value)
        return record

    def test_produces_valid_json(self):
        """Output is valid JSON with expected fields."""
        formatter = StructuredFormatter()
        record = self._make_record()
        output = formatter.format(record)

        data = json.loads(output)
        assert data["level"] == "INFO"
        assert data["logger"] == "acmeeh.test"
        assert data["message"] == "Test message"
        assert "timestamp" in data

    def test_includes_extra_fields(self):
        """Extra fields on the record are included in output."""
        formatter = StructuredFormatter()
        record = self._make_record(custom_field="custom_value")
        output = formatter.format(record)

        data = json.loads(output)
        assert data.get("custom_field") == "custom_value"

    def test_includes_request_context(self):
        """Request context fields (request_id, client_ip) are included."""
        formatter = StructuredFormatter()
        record = self._make_record(
            request_id="req-123",
            client_ip="10.0.0.1",
            account_id="acct-456",
            method="GET",
            path="/directory",
        )
        output = formatter.format(record)

        data = json.loads(output)
        assert data["request_id"] == "req-123"
        assert data["client_ip"] == "10.0.0.1"
        assert data["account_id"] == "acct-456"
        assert data["method"] == "GET"
        assert data["path"] == "/directory"

    def test_includes_exception_info(self):
        """Exception info is included when exc_info is set."""
        formatter = StructuredFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys

            record = self._make_record()
            record.exc_info = sys.exc_info()

        output = formatter.format(record)
        data = json.loads(output)
        assert "exception" in data
        assert "ValueError" in data["exception"]
        assert "test error" in data["exception"]

    def test_omits_none_context_fields(self):
        """Context fields that are None are omitted from output."""
        formatter = StructuredFormatter()
        record = self._make_record()
        # Don't set request_id etc. — they default to not present
        output = formatter.format(record)

        data = json.loads(output)
        assert "request_id" not in data
        assert "client_ip" not in data


# ===========================================================================
# setup.py — TextFormatter
# ===========================================================================


class TestTextFormatter:
    """Tests for TextFormatter."""

    def test_format_string(self):
        """TextFormatter uses the expected format string."""
        formatter = TextFormatter()
        record = logging.LogRecord(
            name="acmeeh.test",
            level=logging.WARNING,
            pathname="test.py",
            lineno=1,
            msg="Something happened",
            args=(),
            exc_info=None,
        )
        record.request_id = "req-abc"
        record.client_ip = "127.0.0.1"

        output = formatter.format(record)
        assert "WARNING" in output
        assert "req-abc" in output
        assert "127.0.0.1" in output
        assert "acmeeh.test" in output
        assert "Something happened" in output


# ===========================================================================
# setup.py — RequestContextFilter
# ===========================================================================


class TestRequestContextFilter:
    """Tests for RequestContextFilter."""

    def test_sets_defaults_when_no_flask_context(self):
        """Without Flask context, defaults are set on the record."""
        ctx_filter = RequestContextFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="msg",
            args=(),
            exc_info=None,
        )

        result = ctx_filter.filter(record)

        assert result is True
        assert record.request_id == "-"
        assert record.client_ip == "-"
        assert record.account_id is None
        assert record.method is None
        assert record.path is None

    def test_injects_flask_context(self):
        """With Flask request context, values from g/request are injected."""
        ctx_filter = RequestContextFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="msg",
            args=(),
            exc_info=None,
        )

        mock_g = MagicMock()
        mock_g.request_id = "req-xyz"
        mock_g.account = MagicMock()
        mock_g.account.id = "acct-789"

        mock_request = MagicMock()
        mock_request.remote_addr = "10.0.0.5"
        mock_request.method = "POST"
        mock_request.path = "/new-order"

        # The imports happen inside the filter method via `from flask import ...`,
        # so we patch at the flask module level.
        with (
            patch("flask.has_request_context", return_value=True),
            patch("flask.g", mock_g),
            patch("flask.request", mock_request),
        ):
            result = ctx_filter.filter(record)

        assert result is True
        assert record.request_id == "req-xyz"
        assert record.client_ip == "10.0.0.5"
        assert record.account_id == "acct-789"
        assert record.method == "POST"
        assert record.path == "/new-order"


# ===========================================================================
# setup.py — configure_logging
# ===========================================================================


class TestConfigureLogging:
    """Tests for configure_logging."""

    def _make_settings(
        self,
        *,
        log_format: str = "json",
        level: str = "INFO",
        audit_enabled: bool = False,
        audit_file: str | None = None,
    ) -> SimpleNamespace:
        """Create mock LoggingSettings."""
        audit = SimpleNamespace(
            enabled=audit_enabled,
            file=audit_file,
            max_file_size_bytes=10485760,
            backup_count=5,
        )
        return SimpleNamespace(
            format=log_format,
            level=level,
            audit=audit,
        )

    def test_json_format(self):
        """configure_logging with json format uses StructuredFormatter."""
        settings = self._make_settings(log_format="json")
        root_logger = configure_logging(settings)

        assert root_logger.name == "acmeeh"
        assert len(root_logger.handlers) == 1
        handler = root_logger.handlers[0]
        assert isinstance(handler.formatter, StructuredFormatter)

    def test_text_format(self):
        """configure_logging with text format uses TextFormatter."""
        settings = self._make_settings(log_format="text")
        root_logger = configure_logging(settings)

        assert len(root_logger.handlers) == 1
        handler = root_logger.handlers[0]
        assert isinstance(handler.formatter, TextFormatter)

    def test_audit_enabled_with_file(self, tmp_path):
        """configure_logging with audit enabled creates a file handler."""
        audit_file = str(tmp_path / "audit.log")
        settings = self._make_settings(
            audit_enabled=True,
            audit_file=audit_file,
        )
        root_logger = configure_logging(settings)

        audit_logger = logging.getLogger("acmeeh.audit")
        # There should be at least one handler (the RotatingFileHandler)
        assert len(audit_logger.handlers) >= 1

        # Clean up
        for handler in audit_logger.handlers[:]:
            handler.close()
            audit_logger.removeHandler(handler)

    def test_sets_log_level(self):
        """configure_logging sets the correct log level."""
        settings = self._make_settings(level="DEBUG")
        root_logger = configure_logging(settings)

        assert root_logger.level == logging.DEBUG

    def test_quietens_third_party_loggers(self):
        """Third-party loggers are set to WARNING level."""
        settings = self._make_settings()
        configure_logging(settings)

        werkzeug_logger = logging.getLogger("werkzeug")
        assert werkzeug_logger.level == logging.WARNING

    def test_clears_existing_handlers(self):
        """Existing handlers on acmeeh logger are cleared."""
        root_logger = logging.getLogger("acmeeh")
        root_logger.addHandler(logging.StreamHandler())
        root_logger.addHandler(logging.StreamHandler())
        assert len(root_logger.handlers) >= 2

        settings = self._make_settings()
        configure_logging(settings)

        # After configure_logging, there should be exactly 1 handler
        assert len(root_logger.handlers) == 1


# ===========================================================================
# audit_cleanup.py
# ===========================================================================


class TestCleanupOldAuditLogs:
    """Tests for cleanup_old_audit_logs."""

    def _make_settings(self, enabled: bool = True, max_age_days: int = 30):
        """Create mock AuditRetentionSettings."""
        return SimpleNamespace(enabled=enabled, max_age_days=max_age_days)

    def test_disabled_returns_zero(self):
        """When disabled, returns 0 immediately."""
        settings = self._make_settings(enabled=False)
        result = cleanup_old_audit_logs(settings, "/var/log/audit.log")
        assert result == 0

    def test_no_audit_file_returns_zero(self):
        """When audit_file is None, returns 0."""
        settings = self._make_settings(enabled=True)
        result = cleanup_old_audit_logs(settings, None)
        assert result == 0

    def test_empty_audit_file_returns_zero(self):
        """When audit_file is empty string, returns 0."""
        settings = self._make_settings(enabled=True)
        result = cleanup_old_audit_logs(settings, "")
        assert result == 0

    def test_deletes_old_files(self, tmp_path):
        """Old rotated audit log files are deleted."""
        # Create the audit log file
        audit_file = tmp_path / "audit.log"
        audit_file.write_text("current")

        # Create old rotated files
        old_file_1 = tmp_path / "audit.log.1"
        old_file_1.write_text("old1")
        old_file_2 = tmp_path / "audit.log.2"
        old_file_2.write_text("old2")

        # Set modification time to 60 days ago
        old_time = time.time() - (60 * 86400)
        os.utime(old_file_1, (old_time, old_time))
        os.utime(old_file_2, (old_time, old_time))

        settings = self._make_settings(enabled=True, max_age_days=30)
        result = cleanup_old_audit_logs(settings, str(audit_file))

        assert result == 2
        assert not old_file_1.exists()
        assert not old_file_2.exists()
        assert audit_file.exists()  # Current file is untouched

    def test_keeps_recent_files(self, tmp_path):
        """Recent rotated files are kept."""
        audit_file = tmp_path / "audit.log"
        audit_file.write_text("current")

        recent_file = tmp_path / "audit.log.1"
        recent_file.write_text("recent")
        # Don't change mtime — it's current

        settings = self._make_settings(enabled=True, max_age_days=30)
        result = cleanup_old_audit_logs(settings, str(audit_file))

        assert result == 0
        assert recent_file.exists()

    def test_handles_oserror_on_unlink(self, tmp_path):
        """OSError on unlink is logged but doesn't crash."""
        audit_file = tmp_path / "audit.log"
        audit_file.write_text("current")

        old_file = tmp_path / "audit.log.1"
        old_file.write_text("old")
        old_time = time.time() - (60 * 86400)
        os.utime(old_file, (old_time, old_time))

        settings = self._make_settings(enabled=True, max_age_days=30)

        with patch.object(Path, "unlink", side_effect=OSError("permission denied")):
            with patch("acmeeh.logging.audit_cleanup.log") as mock_log:
                result = cleanup_old_audit_logs(settings, str(audit_file))

        # File couldn't be deleted, so count is 0
        assert result == 0
        mock_log.warning.assert_called_once()

    def test_nonexistent_parent_returns_zero(self, tmp_path):
        """Non-existent parent directory returns 0."""
        settings = self._make_settings(enabled=True, max_age_days=30)
        result = cleanup_old_audit_logs(
            settings,
            str(tmp_path / "nonexistent" / "audit.log"),
        )
        assert result == 0
