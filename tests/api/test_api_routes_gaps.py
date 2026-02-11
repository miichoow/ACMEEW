"""
Tests covering untested API route code, focusing on _parse_inner_jws from key_change.py.

The _parse_inner_jws function (key_change.py:34-83) is a standalone helper that
parses the inner JWS object in a key-change request. It validates the presence
of 'protected', 'payload', and 'signature' fields, base64url-decodes them,
and returns a parsed result.
"""

import base64
import json

import pytest

from acmeeh.api.key_change import _parse_inner_jws
from acmeeh.app.errors import AcmeProblem


def _b64url(data: bytes) -> str:
    """Base64url-encode bytes without padding, matching ACME/JWS conventions."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class TestParseInnerJws:
    """Tests for _parse_inner_jws (key_change.py lines 34-83)."""

    def test_missing_protected_field(self):
        """Inner JWS without 'protected' raises malformed error."""
        with pytest.raises(AcmeProblem, match="protected"):
            _parse_inner_jws({"payload": "x", "signature": "x"})

    def test_missing_payload_field(self):
        """Inner JWS without 'payload' raises malformed error."""
        with pytest.raises(AcmeProblem, match="payload"):
            _parse_inner_jws({"protected": "x", "signature": "x"})

    def test_missing_signature_field(self):
        """Inner JWS without 'signature' raises malformed error."""
        with pytest.raises(AcmeProblem, match="signature"):
            _parse_inner_jws({"protected": "x", "payload": "x"})

    def test_all_three_fields_missing(self):
        """Empty dict raises malformed error for missing fields."""
        with pytest.raises(AcmeProblem):
            _parse_inner_jws({})

    def test_invalid_protected_encoding(self):
        """Non-base64url 'protected' value raises decode error."""
        with pytest.raises(AcmeProblem, match="(?i)protected"):
            _parse_inner_jws(
                {
                    "protected": "!!!not-valid-base64",
                    "payload": "",
                    "signature": _b64url(b"sig"),
                }
            )

    def test_protected_not_valid_json(self):
        """'protected' that decodes to non-JSON raises error."""
        with pytest.raises(AcmeProblem, match="(?i)protected"):
            _parse_inner_jws(
                {
                    "protected": _b64url(b"this is not json"),
                    "payload": "",
                    "signature": _b64url(b"sig"),
                }
            )

    def test_invalid_payload_encoding(self):
        """Non-base64url 'payload' value raises decode error."""
        protected = _b64url(json.dumps({"alg": "ES256"}).encode())
        with pytest.raises(AcmeProblem, match="(?i)payload"):
            _parse_inner_jws(
                {
                    "protected": protected,
                    "payload": "!!!not-valid-base64",
                    "signature": _b64url(b"sig"),
                }
            )

    def test_invalid_signature_encoding(self):
        """Signature that cannot be base64url-decoded raises error.

        A single character like 'x' produces length 1 which, after padding,
        gives 'x===' -- invalid for base64.b64decode.
        """
        protected = _b64url(json.dumps({"alg": "ES256"}).encode())
        payload = _b64url(json.dumps({"account": "x"}).encode())
        with pytest.raises(AcmeProblem, match="(?i)signature"):
            _parse_inner_jws(
                {
                    "protected": protected,
                    "payload": payload,
                    "signature": "x",
                }
            )

    def test_empty_payload_returns_none_payload(self):
        """Empty string payload is treated as absent (None)."""
        protected = _b64url(json.dumps({"alg": "ES256"}).encode())
        sig = _b64url(b"signature-bytes")
        result = _parse_inner_jws(
            {
                "protected": protected,
                "payload": "",
                "signature": sig,
            }
        )
        assert result.payload is None
        assert result.protected_header == {"alg": "ES256"}

    def test_valid_full_jws_parses_all_fields(self):
        """A well-formed inner JWS is parsed correctly."""
        header = {"alg": "ES256", "jwk": {"kty": "EC", "crv": "P-256"}}
        payload_data = {
            "account": "https://acme.example.com/acct/123",
            "oldKey": {"kty": "EC", "crv": "P-256"},
        }
        protected = _b64url(json.dumps(header).encode())
        payload = _b64url(json.dumps(payload_data).encode())
        sig = _b64url(b"valid-signature-bytes")
        result = _parse_inner_jws(
            {
                "protected": protected,
                "payload": payload,
                "signature": sig,
            }
        )
        assert result.protected_header == header
        assert result.payload == payload_data
        assert result.signature is not None

    def test_valid_jws_with_rsa_algorithm(self):
        """Inner JWS with RS256 algorithm parses correctly."""
        header = {"alg": "RS256", "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"}}
        payload_data = {
            "account": "https://acme.example.com/acct/456",
            "oldKey": {"kty": "RSA", "n": "xyz", "e": "AQAB"},
        }
        protected = _b64url(json.dumps(header).encode())
        payload = _b64url(json.dumps(payload_data).encode())
        sig = _b64url(b"rsa-signature-bytes")
        result = _parse_inner_jws(
            {
                "protected": protected,
                "payload": payload,
                "signature": sig,
            }
        )
        assert result.protected_header["alg"] == "RS256"
        assert result.payload["account"] == "https://acme.example.com/acct/456"

    def test_payload_with_unicode_content(self):
        """Payload containing unicode characters parses correctly."""
        header = {"alg": "ES256"}
        payload_data = {"account": "https://acme.example.com/acct/789", "note": "test-value"}
        protected = _b64url(json.dumps(header).encode())
        payload = _b64url(json.dumps(payload_data).encode())
        sig = _b64url(b"sig")
        result = _parse_inner_jws(
            {
                "protected": protected,
                "payload": payload,
                "signature": sig,
            }
        )
        assert result.payload["note"] == "test-value"

    def test_signature_bytes_preserved(self):
        """The raw signature bytes are correctly decoded and available."""
        header = {"alg": "ES256"}
        payload_data = {"account": "https://acme.example.com/acct/1"}
        raw_sig = b"\x00\x01\x02\x03\xff\xfe\xfd"
        protected = _b64url(json.dumps(header).encode())
        payload = _b64url(json.dumps(payload_data).encode())
        sig = _b64url(raw_sig)
        result = _parse_inner_jws(
            {
                "protected": protected,
                "payload": payload,
                "signature": sig,
            }
        )
        assert result.signature == raw_sig

    def test_protected_header_with_extra_fields(self):
        """Extra fields in protected header are preserved."""
        header = {"alg": "ES384", "url": "https://acme.example.com/key-change", "nonce": "abc123"}
        payload_data = {"account": "https://acme.example.com/acct/5"}
        protected = _b64url(json.dumps(header).encode())
        payload = _b64url(json.dumps(payload_data).encode())
        sig = _b64url(b"sig")
        result = _parse_inner_jws(
            {
                "protected": protected,
                "payload": payload,
                "signature": sig,
            }
        )
        assert result.protected_header["url"] == "https://acme.example.com/key-change"
        assert result.protected_header["nonce"] == "abc123"
        assert result.protected_header["alg"] == "ES384"

    def test_b64_fields_preserved(self):
        """Original base64url strings are stored in protected_b64, payload_b64, signature_b64."""
        header = {"alg": "ES256"}
        payload_data = {"account": "https://acme.example.com/acct/1"}
        protected = _b64url(json.dumps(header).encode())
        payload = _b64url(json.dumps(payload_data).encode())
        sig = _b64url(b"sig")
        result = _parse_inner_jws(
            {
                "protected": protected,
                "payload": payload,
                "signature": sig,
            }
        )
        assert result.protected_b64 == protected
        assert result.payload_b64 == payload
        assert result.signature_b64 == sig

    def test_algorithm_property(self):
        """JWSObject.algorithm returns the 'alg' from the protected header."""
        header = {"alg": "ES384"}
        payload_data = {"account": "https://acme.example.com/acct/1"}
        protected = _b64url(json.dumps(header).encode())
        payload = _b64url(json.dumps(payload_data).encode())
        sig = _b64url(b"sig")
        result = _parse_inner_jws(
            {
                "protected": protected,
                "payload": payload,
                "signature": sig,
            }
        )
        assert result.algorithm == "ES384"

    def test_payload_not_valid_json(self):
        """Non-empty payload that is not valid JSON raises decode error."""
        protected = _b64url(json.dumps({"alg": "ES256"}).encode())
        payload = _b64url(b"not-json-content")
        sig = _b64url(b"sig")
        with pytest.raises(AcmeProblem, match="(?i)payload"):
            _parse_inner_jws(
                {
                    "protected": protected,
                    "payload": payload,
                    "signature": sig,
                }
            )
