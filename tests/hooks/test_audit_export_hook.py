"""Tests for acmeeh.hooks.audit_export_hook.AuditWebhookHook."""

from __future__ import annotations

import json
from unittest.mock import patch

from acmeeh.hooks.audit_export_hook import AuditWebhookHook

# ---------------------------------------------------------------------------
# _send
# ---------------------------------------------------------------------------


class TestAuditWebhookHookSend:
    """Tests for AuditWebhookHook._send."""

    @patch("urllib.request.urlopen")
    def test_send_with_url_posts_json(self, mock_urlopen):
        """_send with a configured URL sends JSON POST request."""
        hook = AuditWebhookHook(
            config={
                "webhook_url": "https://siem.example.com/hook",
                "timeout_seconds": 5,
            }
        )

        hook._send("test.event", {"key": "value"})

        mock_urlopen.assert_called_once()
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert req.full_url == "https://siem.example.com/hook"
        assert req.method == "POST"
        assert req.get_header("Content-type") == "application/json"

        payload = json.loads(req.data.decode("utf-8"))
        assert payload["event"] == "test.event"
        assert payload["data"] == {"key": "value"}

    def test_send_with_empty_url_is_noop(self):
        """_send with empty URL does nothing (no-op)."""
        hook = AuditWebhookHook(config={"webhook_url": ""})

        with patch("urllib.request.urlopen") as mock_urlopen:
            hook._send("test.event", {"key": "value"})

        mock_urlopen.assert_not_called()

    def test_send_with_no_url_is_noop(self):
        """_send with no webhook_url in config does nothing."""
        hook = AuditWebhookHook(config={})

        with patch("urllib.request.urlopen") as mock_urlopen:
            hook._send("test.event", {"key": "value"})

        mock_urlopen.assert_not_called()

    @patch("urllib.request.urlopen")
    def test_send_handles_exception_gracefully(self, mock_urlopen):
        """_send catches exceptions and logs them, does not raise."""
        mock_urlopen.side_effect = ConnectionError("refused")

        hook = AuditWebhookHook(
            config={
                "webhook_url": "https://siem.example.com/hook",
            }
        )

        with patch("acmeeh.hooks.audit_export_hook.log") as mock_log:
            # Should not raise
            hook._send("test.event", {"key": "value"})

        mock_log.exception.assert_called_once()
        assert "test.event" in mock_log.exception.call_args[0][1]


# ---------------------------------------------------------------------------
# Event methods
# ---------------------------------------------------------------------------


class TestAuditWebhookHookEvents:
    """Tests for the event handler methods."""

    @patch.object(AuditWebhookHook, "_send")
    def test_on_certificate_issuance(self, mock_send):
        """on_certificate_issuance calls _send with correct event name."""
        hook = AuditWebhookHook(config={"webhook_url": "https://siem.example.com"})
        data = {"certificate_id": "cert-1", "serial_number": "ABC"}

        hook.on_certificate_issuance(data)

        mock_send.assert_called_once_with("certificate.issuance", data)

    @patch.object(AuditWebhookHook, "_send")
    def test_on_certificate_revocation(self, mock_send):
        """on_certificate_revocation calls _send with correct event name."""
        hook = AuditWebhookHook(config={"webhook_url": "https://siem.example.com"})
        data = {"certificate_id": "cert-1", "reason": "keyCompromise"}

        hook.on_certificate_revocation(data)

        mock_send.assert_called_once_with("certificate.revocation", data)

    @patch.object(AuditWebhookHook, "_send")
    def test_on_account_registration(self, mock_send):
        """on_account_registration calls _send with correct event name."""
        hook = AuditWebhookHook(config={"webhook_url": "https://siem.example.com"})
        data = {"account_id": "acct-1", "contacts": ["mailto:a@b.com"]}

        hook.on_account_registration(data)

        mock_send.assert_called_once_with("account.registration", data)

    @patch("urllib.request.urlopen")
    def test_on_certificate_issuance_full_round_trip(self, mock_urlopen):
        """Full integration: issuance event posts to webhook URL."""
        hook = AuditWebhookHook(
            config={
                "webhook_url": "https://siem.example.com/hook",
                "timeout_seconds": 3,
            }
        )
        data = {"certificate_id": "cert-1"}

        hook.on_certificate_issuance(data)

        mock_urlopen.assert_called_once()
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        payload = json.loads(req.data.decode("utf-8"))
        assert payload["event"] == "certificate.issuance"
        assert payload["data"] == data

    @patch("urllib.request.urlopen")
    def test_timeout_passed_to_urlopen(self, mock_urlopen):
        """Custom timeout is passed through to urlopen."""
        hook = AuditWebhookHook(
            config={
                "webhook_url": "https://siem.example.com/hook",
                "timeout_seconds": 7,
            }
        )

        hook._send("test.event", {})

        mock_urlopen.assert_called_once()
        call_args = mock_urlopen.call_args
        # urlopen is called as urlopen(req, timeout=7)
        assert call_args[1]["timeout"] == 7
