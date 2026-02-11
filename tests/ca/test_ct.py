"""Comprehensive unit tests for acmeeh.ca.ct (CTPreCertSubmitter and encode_sct_list)."""

from __future__ import annotations

import base64
import json
import struct
import urllib.error
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from acmeeh.ca.ct import CTPreCertSubmitter, encode_sct_list

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ct_log(
    url: str = "https://ct.example.com",
    timeout: int = 5,
) -> MagicMock:
    """Build a mock CtLogEntry."""
    log_entry = MagicMock()
    log_entry.url = url
    log_entry.timeout_seconds = timeout
    log_entry.public_key_path = None
    return log_entry


def _make_ct_settings(logs: list | None = None) -> MagicMock:
    """Build a mock CtLoggingSettings."""
    settings = MagicMock()
    settings.logs = logs or []
    settings.enabled = True
    settings.submit_precert = True
    return settings


def _make_sct_response(
    sct_version: int = 0,
    log_id_bytes: bytes = b"\x01" * 32,
    timestamp: int = 1700000000000,
    extensions: str = "",
    signature_bytes: bytes = b"\x04\x03\x00\x04test",
) -> dict:
    """Build a well-formed SCT response dict."""
    return {
        "sct_version": sct_version,
        "id": base64.b64encode(log_id_bytes).decode(),
        "timestamp": timestamp,
        "extensions": base64.b64encode(extensions.encode()).decode() if extensions else "",
        "signature": base64.b64encode(signature_bytes).decode(),
    }


def _make_urlopen_response(body: dict) -> MagicMock:
    """Build a mock response for urllib.request.urlopen."""
    response = MagicMock()
    response.read.return_value = json.dumps(body).encode("utf-8")
    return response


# ---------------------------------------------------------------------------
# Tests: CTPreCertSubmitter.submit_precert
# ---------------------------------------------------------------------------


class TestSubmitPrecert:
    """Tests for CTPreCertSubmitter.submit_precert."""

    @patch("acmeeh.ca.ct.urllib.request.urlopen")
    def test_successful_submission(self, mock_urlopen: MagicMock) -> None:
        """Successful submission returns the SCT dict."""
        sct_body = _make_sct_response()
        mock_urlopen.return_value = _make_urlopen_response(sct_body)

        ct_log = _make_ct_log("https://ct1.example.com")
        settings = _make_ct_settings(logs=[ct_log])
        submitter = CTPreCertSubmitter(settings)

        scts = submitter.submit_precert(b"\x30\x82\x01\x00")

        assert len(scts) == 1
        assert scts[0]["sct_version"] == 0
        assert scts[0]["timestamp"] == 1700000000000
        mock_urlopen.assert_called_once()

        # Verify the request was POST to the correct URL
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert req.full_url == "https://ct1.example.com/ct/v1/add-pre-chain"
        assert req.method == "POST"

    @patch("acmeeh.ca.ct.urllib.request.urlopen")
    def test_multiple_logs(self, mock_urlopen: MagicMock) -> None:
        """Test submission to multiple logs, all succeed."""
        sct1 = _make_sct_response(timestamp=100)
        sct2 = _make_sct_response(timestamp=200)
        mock_urlopen.side_effect = [
            _make_urlopen_response(sct1),
            _make_urlopen_response(sct2),
        ]

        log1 = _make_ct_log("https://ct1.example.com")
        log2 = _make_ct_log("https://ct2.example.com")
        settings = _make_ct_settings(logs=[log1, log2])
        submitter = CTPreCertSubmitter(settings)

        scts = submitter.submit_precert(b"fake-der")
        assert len(scts) == 2
        assert scts[0]["timestamp"] == 100
        assert scts[1]["timestamp"] == 200

    @patch("acmeeh.ca.ct.urllib.request.urlopen")
    def test_http_error_continues_to_next(self, mock_urlopen: MagicMock) -> None:
        """HTTPError on first log should not prevent second log from working."""
        http_err = urllib.error.HTTPError(
            "https://ct1.example.com/ct/v1/add-pre-chain",
            500,
            "Internal Server Error",
            {},
            BytesIO(b"error"),
        )
        sct2 = _make_sct_response(timestamp=999)
        mock_urlopen.side_effect = [
            http_err,
            _make_urlopen_response(sct2),
        ]

        log1 = _make_ct_log("https://ct1.example.com")
        log2 = _make_ct_log("https://ct2.example.com")
        settings = _make_ct_settings(logs=[log1, log2])
        submitter = CTPreCertSubmitter(settings)

        scts = submitter.submit_precert(b"fake-der")
        assert len(scts) == 1
        assert scts[0]["timestamp"] == 999

    @patch("acmeeh.ca.ct.urllib.request.urlopen")
    def test_url_error_continues(self, mock_urlopen: MagicMock) -> None:
        """URLError (network error) should continue to next log."""
        url_err = urllib.error.URLError("Connection refused")
        sct2 = _make_sct_response(timestamp=888)
        mock_urlopen.side_effect = [
            url_err,
            _make_urlopen_response(sct2),
        ]

        log1 = _make_ct_log("https://ct1.example.com")
        log2 = _make_ct_log("https://ct2.example.com")
        settings = _make_ct_settings(logs=[log1, log2])
        submitter = CTPreCertSubmitter(settings)

        scts = submitter.submit_precert(b"fake-der")
        assert len(scts) == 1
        assert scts[0]["timestamp"] == 888

    @patch("acmeeh.ca.ct.urllib.request.urlopen")
    def test_json_decode_error_continues(self, mock_urlopen: MagicMock) -> None:
        """Invalid JSON response should continue to next log."""
        bad_response = MagicMock()
        bad_response.read.return_value = b"not-json{{"

        sct2 = _make_sct_response(timestamp=777)
        mock_urlopen.side_effect = [
            bad_response,
            _make_urlopen_response(sct2),
        ]

        log1 = _make_ct_log("https://ct1.example.com")
        log2 = _make_ct_log("https://ct2.example.com")
        settings = _make_ct_settings(logs=[log1, log2])
        submitter = CTPreCertSubmitter(settings)

        scts = submitter.submit_precert(b"fake-der")
        # The first log's JSONDecodeError is raised by _submit_to_log and
        # caught by submit_precert. The second should succeed.
        assert len(scts) == 1
        assert scts[0]["timestamp"] == 777

    @patch("acmeeh.ca.ct.urllib.request.urlopen")
    def test_os_error_continues(self, mock_urlopen: MagicMock) -> None:
        """OSError should continue to next log."""
        mock_urlopen.side_effect = [
            OSError("socket timeout"),
            _make_urlopen_response(_make_sct_response(timestamp=666)),
        ]

        log1 = _make_ct_log("https://ct1.example.com")
        log2 = _make_ct_log("https://ct2.example.com")
        settings = _make_ct_settings(logs=[log1, log2])
        submitter = CTPreCertSubmitter(settings)

        scts = submitter.submit_precert(b"fake-der")
        assert len(scts) == 1
        assert scts[0]["timestamp"] == 666

    @patch("acmeeh.ca.ct.urllib.request.urlopen")
    def test_value_error_continues(self, mock_urlopen: MagicMock) -> None:
        """ValueError should continue to next log."""
        mock_urlopen.side_effect = [
            ValueError("bad url"),
            _make_urlopen_response(_make_sct_response(timestamp=555)),
        ]

        log1 = _make_ct_log("https://ct1.example.com")
        log2 = _make_ct_log("https://ct2.example.com")
        settings = _make_ct_settings(logs=[log1, log2])
        submitter = CTPreCertSubmitter(settings)

        scts = submitter.submit_precert(b"fake-der")
        assert len(scts) == 1

    @patch("acmeeh.ca.ct.urllib.request.urlopen")
    def test_all_logs_fail_returns_empty(self, mock_urlopen: MagicMock) -> None:
        """If all logs fail, return empty list (no crash)."""
        mock_urlopen.side_effect = urllib.error.URLError("fail")

        log1 = _make_ct_log("https://ct1.example.com")
        log2 = _make_ct_log("https://ct2.example.com")
        settings = _make_ct_settings(logs=[log1, log2])
        submitter = CTPreCertSubmitter(settings)

        scts = submitter.submit_precert(b"fake-der")
        assert scts == []

    def test_no_logs_configured(self) -> None:
        """Empty logs list should return empty SCTs."""
        settings = _make_ct_settings(logs=[])
        submitter = CTPreCertSubmitter(settings)
        scts = submitter.submit_precert(b"fake-der")
        assert scts == []

    @patch("acmeeh.ca.ct.urllib.request.urlopen")
    def test_url_trailing_slash_stripped(self, mock_urlopen: MagicMock) -> None:
        """CT log URL trailing slash should be stripped before appending path."""
        mock_urlopen.return_value = _make_urlopen_response(_make_sct_response())

        ct_log = _make_ct_log("https://ct.example.com/")
        settings = _make_ct_settings(logs=[ct_log])
        submitter = CTPreCertSubmitter(settings)
        submitter.submit_precert(b"fake-der")

        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://ct.example.com/ct/v1/add-pre-chain"


# ---------------------------------------------------------------------------
# Tests: CTPreCertSubmitter._submit_to_log
# ---------------------------------------------------------------------------


class TestSubmitToLog:
    """Tests for _submit_to_log internal method."""

    @patch("acmeeh.ca.ct.urllib.request.urlopen")
    def test_returns_parsed_sct(self, mock_urlopen: MagicMock) -> None:
        sct_body = _make_sct_response(sct_version=0, timestamp=42)
        mock_urlopen.return_value = _make_urlopen_response(sct_body)

        settings = _make_ct_settings()
        submitter = CTPreCertSubmitter(settings)
        ct_log = _make_ct_log()

        result = submitter._submit_to_log(ct_log, "base64data")
        assert result is not None
        assert result["sct_version"] == 0
        assert result["timestamp"] == 42

    @patch("acmeeh.ca.ct.urllib.request.urlopen")
    def test_http_error_re_raised(self, mock_urlopen: MagicMock) -> None:
        http_err = urllib.error.HTTPError(
            "https://ct.example.com/ct/v1/add-pre-chain",
            400,
            "Bad Request",
            {},
            BytesIO(b"bad request"),
        )
        mock_urlopen.side_effect = http_err

        settings = _make_ct_settings()
        submitter = CTPreCertSubmitter(settings)
        ct_log = _make_ct_log()

        with pytest.raises(urllib.error.HTTPError):
            submitter._submit_to_log(ct_log, "base64data")

    @patch("acmeeh.ca.ct.urllib.request.urlopen")
    def test_url_error_re_raised(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = urllib.error.URLError("timeout")

        settings = _make_ct_settings()
        submitter = CTPreCertSubmitter(settings)
        ct_log = _make_ct_log()

        with pytest.raises(urllib.error.URLError):
            submitter._submit_to_log(ct_log, "base64data")

    @patch("acmeeh.ca.ct.urllib.request.urlopen")
    def test_json_decode_error_re_raised(self, mock_urlopen: MagicMock) -> None:
        bad_response = MagicMock()
        bad_response.read.return_value = b"<html>not json</html>"
        mock_urlopen.return_value = bad_response

        settings = _make_ct_settings()
        submitter = CTPreCertSubmitter(settings)
        ct_log = _make_ct_log()

        with pytest.raises(json.JSONDecodeError):
            submitter._submit_to_log(ct_log, "base64data")

    @patch("acmeeh.ca.ct.urllib.request.urlopen")
    def test_os_error_re_raised(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.side_effect = OSError("socket error")

        settings = _make_ct_settings()
        submitter = CTPreCertSubmitter(settings)
        ct_log = _make_ct_log()

        with pytest.raises(OSError):
            submitter._submit_to_log(ct_log, "base64data")


# ---------------------------------------------------------------------------
# Tests: encode_sct_list
# ---------------------------------------------------------------------------


class TestEncodeSctList:
    """Tests for the encode_sct_list function."""

    def test_single_sct_encoding(self) -> None:
        """Verify basic wire format for a single SCT."""
        log_id = b"\xaa" * 32
        timestamp = 1700000000000
        sig_bytes = b"\x04\x03\x00\x04test"

        sct = {
            "sct_version": 0,
            "id": base64.b64encode(log_id).decode(),
            "timestamp": timestamp,
            "extensions": "",
            "signature": base64.b64encode(sig_bytes).decode(),
        }

        result = encode_sct_list([sct])

        # Parse the outer length prefix
        outer_len = struct.unpack(">H", result[:2])[0]
        assert outer_len == len(result) - 2

        # Parse the SCT length prefix
        sct_len = struct.unpack(">H", result[2:4])[0]
        sct_data = result[4 : 4 + sct_len]

        # Version byte
        assert sct_data[0] == 0

        # Log ID (32 bytes)
        assert sct_data[1:33] == log_id

        # Timestamp (8 bytes)
        ts = struct.unpack(">Q", sct_data[33:41])[0]
        assert ts == timestamp

        # Extensions length (2 bytes) = 0
        ext_len = struct.unpack(">H", sct_data[41:43])[0]
        assert ext_len == 0

        # Signature
        assert sct_data[43:] == sig_bytes

    def test_multiple_scts(self) -> None:
        """Multiple SCTs should be concatenated properly."""
        sct1 = _make_sct_response(timestamp=100)
        sct2 = _make_sct_response(timestamp=200)

        result = encode_sct_list([sct1, sct2])

        # Outer length
        outer_len = struct.unpack(">H", result[:2])[0]
        assert outer_len == len(result) - 2

        # Count SCTs by parsing length-prefixed entries
        offset = 2
        count = 0
        while offset < len(result):
            entry_len = struct.unpack(">H", result[offset : offset + 2])[0]
            offset += 2 + entry_len
            count += 1
        assert count == 2

    def test_wrong_length_log_id_padded(self) -> None:
        """Log ID shorter than 32 bytes should be padded with zeros."""
        short_id = b"\xbb" * 16  # only 16 bytes
        sct = {
            "sct_version": 0,
            "id": base64.b64encode(short_id).decode(),
            "timestamp": 0,
            "extensions": "",
            "signature": base64.b64encode(b"\x04\x03\x00\x00").decode(),
        }

        result = encode_sct_list([sct])

        # Skip outer len (2) + sct len (2) + version (1)
        log_id_in_wire = result[5:37]
        assert len(log_id_in_wire) == 32
        assert log_id_in_wire[:16] == short_id
        assert log_id_in_wire[16:] == b"\x00" * 16

    def test_wrong_length_log_id_truncated(self) -> None:
        """Log ID longer than 32 bytes should be truncated."""
        long_id = b"\xcc" * 48  # 48 bytes
        sct = {
            "sct_version": 0,
            "id": base64.b64encode(long_id).decode(),
            "timestamp": 0,
            "extensions": "",
            "signature": base64.b64encode(b"\x04\x03\x00\x00").decode(),
        }

        result = encode_sct_list([sct])

        log_id_in_wire = result[5:37]
        assert len(log_id_in_wire) == 32
        assert log_id_in_wire == long_id[:32]

    def test_no_signature_placeholder(self) -> None:
        """Missing signature should produce a minimal placeholder."""
        sct = {
            "sct_version": 0,
            "id": base64.b64encode(b"\x00" * 32).decode(),
            "timestamp": 0,
            "extensions": "",
            "signature": "",  # empty = no signature
        }

        result = encode_sct_list([sct])

        # Skip outer len (2) + sct len (2) + version (1) + log_id (32) +
        # timestamp (8) + ext_len (2) = 47
        # Placeholder: \x04\x03\x00\x00
        sig_data = result[47:]
        assert sig_data == b"\x04\x03\x00\x00"

    def test_sct_with_extensions(self) -> None:
        """SCT with non-empty extensions should encode them properly."""
        ext_data = b"\x01\x02\x03\x04"
        sct = {
            "sct_version": 0,
            "id": base64.b64encode(b"\xdd" * 32).decode(),
            "timestamp": 5000,
            "extensions": base64.b64encode(ext_data).decode(),
            "signature": base64.b64encode(b"\x04\x03\x00\x00").decode(),
        }

        result = encode_sct_list([sct])

        # Parse to find extensions
        # outer_len(2) + sct_len(2) + version(1) + log_id(32) + timestamp(8) = 45
        ext_len = struct.unpack(">H", result[45:47])[0]
        assert ext_len == 4
        assert result[47:51] == ext_data

    def test_empty_list(self) -> None:
        """Empty SCT list should encode as just the outer length prefix of 0."""
        result = encode_sct_list([])
        assert result == b"\x00\x00"

    def test_sct_version_clamped_to_byte(self) -> None:
        """sct_version should be masked to a single byte."""
        sct = {
            "sct_version": 256,  # 0x100 -> should be 0x00 after & 0xFF
            "id": base64.b64encode(b"\x00" * 32).decode(),
            "timestamp": 0,
            "extensions": "",
            "signature": base64.b64encode(b"\x04\x03\x00\x00").decode(),
        }
        result = encode_sct_list([sct])
        # version byte at offset 4 (outer_len=2 + sct_len=2)
        assert result[4] == 0

    def test_sct_default_values(self) -> None:
        """SCT with missing keys should use defaults."""
        sct: dict = {}  # all missing
        result = encode_sct_list([sct])
        # Should not crash; uses defaults (version=0, empty id, timestamp=0, etc.)
        assert len(result) > 2
