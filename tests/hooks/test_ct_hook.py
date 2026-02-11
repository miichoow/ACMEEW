"""Tests for acmeeh.hooks.ct_hook.CTSubmissionHook."""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from acmeeh.hooks.ct_hook import CTSubmissionHook

# ---------------------------------------------------------------------------
# Sample PEM chain for testing
# ---------------------------------------------------------------------------

_SAMPLE_PEM_CHAIN = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBkTCB+wIJALRiMLAh0EHJMA0GCSqGSIb3DQEBCwUA\n"
    "MBExDzANBgNVBAMMBnJvb3RjYTAeFw0yNDAxMDEwMDAw\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBkTCB+wIJALRiMLAh0EHKxyzGCSqGSIb3DQEBCwUA\n"
    "MBExDzANBgNVBAMMBmlzc3VlcjAeFw0yNDAxMDEwMDAw\n"
    "-----END CERTIFICATE-----\n"
)


# ---------------------------------------------------------------------------
# validate_config
# ---------------------------------------------------------------------------


class TestCTSubmissionHookValidateConfig:
    """Tests for CTSubmissionHook.validate_config."""

    def test_valid_config(self):
        """Valid config with a list of log entries passes validation."""
        config = {
            "logs": [
                {"url": "https://ct-log.example.com"},
                {"url": "https://ct-log2.example.com", "timeout_seconds": 5},
            ],
        }
        # Should not raise
        CTSubmissionHook.validate_config(config)

    def test_logs_not_a_list_raises(self):
        """Config with 'logs' not being a list raises ValueError."""
        config = {"logs": "not-a-list"}
        with pytest.raises(ValueError, match="must be a list"):
            CTSubmissionHook.validate_config(config)

    def test_entry_missing_url_raises(self):
        """Log entry without 'url' raises ValueError."""
        config = {"logs": [{"timeout_seconds": 10}]}
        with pytest.raises(ValueError, match="must have a 'url'"):
            CTSubmissionHook.validate_config(config)

    def test_entry_not_a_dict_raises(self):
        """Log entry that is not a dict raises ValueError."""
        config = {"logs": ["just-a-string"]}
        with pytest.raises(ValueError, match="must have a 'url'"):
            CTSubmissionHook.validate_config(config)

    def test_empty_logs_list_is_valid(self):
        """Empty logs list is valid (nothing to submit to)."""
        config = {"logs": []}
        CTSubmissionHook.validate_config(config)

    def test_no_logs_key_uses_default_empty_list(self):
        """Missing 'logs' key defaults to empty list — valid."""
        config = {}
        CTSubmissionHook.validate_config(config)


# ---------------------------------------------------------------------------
# on_certificate_issuance
# ---------------------------------------------------------------------------


class TestCTSubmissionHookOnIssuance:
    """Tests for CTSubmissionHook.on_certificate_issuance."""

    def test_no_pem_chain_skips(self):
        """Empty pem_chain in context -> skip (no submission)."""
        hook = CTSubmissionHook(
            config={
                "logs": [{"url": "https://ct.example.com"}],
            }
        )
        ctx = {"serial_number": "ABC123"}
        # Should not raise, and should log a warning
        with patch("acmeeh.hooks.ct_hook.log") as mock_log:
            hook.on_certificate_issuance(ctx)
        mock_log.warning.assert_called_once()
        assert "no pem_chain" in mock_log.warning.call_args[0][0]

    @patch.object(CTSubmissionHook, "_submit_to_log")
    def test_calls_submit_for_each_log(self, mock_submit):
        """Calls _submit_to_log once for each configured CT log."""
        hook = CTSubmissionHook(
            config={
                "logs": [
                    {"url": "https://ct1.example.com"},
                    {"url": "https://ct2.example.com"},
                ],
            }
        )
        ctx = {"pem_chain": _SAMPLE_PEM_CHAIN, "serial_number": "ABC123"}

        hook.on_certificate_issuance(ctx)

        assert mock_submit.call_count == 2
        calls = mock_submit.call_args_list
        assert calls[0][0][0]["url"] == "https://ct1.example.com"
        assert calls[1][0][0]["url"] == "https://ct2.example.com"

    @patch.object(CTSubmissionHook, "_submit_to_log")
    def test_submit_failure_logs_exception(self, mock_submit):
        """Exception from _submit_to_log is caught and logged."""
        mock_submit.side_effect = Exception("connection failed")

        hook = CTSubmissionHook(
            config={
                "logs": [{"url": "https://ct.example.com"}],
            }
        )
        ctx = {"pem_chain": _SAMPLE_PEM_CHAIN, "serial_number": "ABC123"}

        with patch("acmeeh.hooks.ct_hook.log") as mock_log:
            hook.on_certificate_issuance(ctx)
        mock_log.exception.assert_called_once()


# ---------------------------------------------------------------------------
# _submit_to_log
# ---------------------------------------------------------------------------


class TestCTSubmissionHookSubmitToLog:
    """Tests for CTSubmissionHook._submit_to_log."""

    @patch("acmeeh.hooks.ct_hook.urllib.request.urlopen")
    def test_parses_pem_chain_correctly(self, mock_urlopen):
        """Extracts base64 DER blocks from PEM chain."""
        sct_response = json.dumps({"sct_version": 0}).encode("utf-8")
        mock_resp = MagicMock()
        mock_resp.read.return_value = sct_response
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        hook = CTSubmissionHook(config={})
        ct_log = {"url": "https://ct.example.com", "timeout_seconds": 5}
        ctx = {"serial_number": "ABC123"}

        result = hook._submit_to_log(ct_log, _SAMPLE_PEM_CHAIN, ctx)

        assert result is not None
        assert result["sct_version"] == 0

        # Verify the request payload has a chain with 2 entries
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        payload = json.loads(req.data.decode("utf-8"))
        assert len(payload["chain"]) == 2

    @patch("acmeeh.hooks.ct_hook.urllib.request.urlopen")
    def test_submit_url_is_correct(self, mock_urlopen):
        """URL is constructed as {base_url}/ct/v1/add-chain."""
        sct_response = json.dumps({"sct_version": 0}).encode("utf-8")
        mock_resp = MagicMock()
        mock_resp.read.return_value = sct_response
        mock_urlopen.return_value = mock_resp

        hook = CTSubmissionHook(config={})
        ct_log = {"url": "https://ct.example.com/"}
        ctx = {"serial_number": "ABC123"}

        hook._submit_to_log(ct_log, _SAMPLE_PEM_CHAIN, ctx)

        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert req.full_url == "https://ct.example.com/ct/v1/add-chain"

    @patch("acmeeh.hooks.ct_hook.urllib.request.urlopen")
    def test_handles_http_error(self, mock_urlopen):
        """HTTPError from CT log is re-raised after logging."""
        import io

        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://ct.example.com/ct/v1/add-chain",
            code=400,
            msg="Bad Request",
            hdrs=MagicMock(),
            fp=io.BytesIO(b"invalid chain"),
        )

        hook = CTSubmissionHook(config={})
        ct_log = {"url": "https://ct.example.com"}
        ctx = {"serial_number": "ABC123"}

        with pytest.raises(urllib.error.HTTPError):
            hook._submit_to_log(ct_log, _SAMPLE_PEM_CHAIN, ctx)

    @patch("acmeeh.hooks.ct_hook.urllib.request.urlopen")
    def test_handles_generic_exception(self, mock_urlopen):
        """Generic exception is re-raised after logging."""
        mock_urlopen.side_effect = ConnectionError("refused")

        hook = CTSubmissionHook(config={})
        ct_log = {"url": "https://ct.example.com"}
        ctx = {"serial_number": "ABC123"}

        with pytest.raises(ConnectionError):
            hook._submit_to_log(ct_log, _SAMPLE_PEM_CHAIN, ctx)
