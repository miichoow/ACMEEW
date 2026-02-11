"""Tests for acmeeh.challenge.tls_alpn01 — TLS-ALPN-01 validator and DER parser."""

from __future__ import annotations

import hashlib
import ipaddress
import ssl
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier

from acmeeh.challenge.base import ChallengeError
from acmeeh.challenge.tls_alpn01 import (
    _ACME_IDENTIFIER_OID,
    _ACME_TLS_ALPN,
    TlsAlpn01Validator,
    _parse_acme_identifier_extension,
)
from acmeeh.core.types import ChallengeType

# ---------------------------------------------------------------------------
# _parse_acme_identifier_extension
# ---------------------------------------------------------------------------


class TestParseAcmeIdentifierExtension:
    """Tests for the DER OCTET STRING parser."""

    def test_valid_32_byte_octet_string(self):
        """Valid DER: tag 0x04, length 0x20, 32 bytes of data."""
        digest = b"\xab" * 32
        der = b"\x04\x20" + digest
        result = _parse_acme_identifier_extension(der)
        assert result == digest

    def test_der_too_short(self):
        """DER less than 2 bytes should raise ChallengeError."""
        with pytest.raises(ChallengeError, match="DER too short"):
            _parse_acme_identifier_extension(b"\x04")

    def test_der_empty(self):
        """Empty bytes should raise ChallengeError."""
        with pytest.raises(ChallengeError, match="DER too short"):
            _parse_acme_identifier_extension(b"")

    def test_wrong_tag(self):
        """Tag byte that is not 0x04 should raise ChallengeError."""
        der = b"\x30\x20" + b"\x00" * 32  # SEQUENCE tag instead of OCTET STRING
        with pytest.raises(ChallengeError, match="expected OCTET STRING tag"):
            _parse_acme_identifier_extension(der)

    def test_indefinite_length(self):
        """Indefinite-length encoding (0x80) is not allowed in DER."""
        der = b"\x04\x80" + b"\x00" * 32 + b"\x00\x00"
        with pytest.raises(ChallengeError, match="indefinite-length"):
            _parse_acme_identifier_extension(der)

    def test_long_form_length(self):
        """Long-form length encoding should work correctly for 32 bytes."""
        digest = b"\xcd" * 32
        # Long form: 0x81 means 1 byte follows for length, then 0x20 = 32
        der = b"\x04\x81\x20" + digest
        result = _parse_acme_identifier_extension(der)
        assert result == digest

    def test_truncated_length_field(self):
        """Long-form length that claims more bytes than available."""
        # 0x82 means 2 length bytes follow, but only 1 is present
        der = b"\x04\x82\x00"
        with pytest.raises(ChallengeError, match="truncated DER length field"):
            _parse_acme_identifier_extension(der)

    def test_length_mismatch_too_many_bytes(self):
        """Declared length doesn't match actual remaining bytes."""
        # Tag=0x04, Length=0x10 (16), but 32 bytes follow
        der = b"\x04\x10" + b"\x00" * 32
        with pytest.raises(ChallengeError, match="DER length mismatch"):
            _parse_acme_identifier_extension(der)

    def test_length_mismatch_too_few_bytes(self):
        """Declared length exceeds actual remaining bytes."""
        der = b"\x04\x20" + b"\x00" * 16
        with pytest.raises(ChallengeError, match="DER length mismatch"):
            _parse_acme_identifier_extension(der)

    def test_wrong_digest_length_too_short(self):
        """Digest that is not 32 bytes (too short) should raise."""
        der = b"\x04\x10" + b"\x00" * 16
        with pytest.raises(ChallengeError, match="expected 32-byte SHA-256 digest"):
            _parse_acme_identifier_extension(der)

    def test_wrong_digest_length_too_long(self):
        """Digest that is not 32 bytes (too long) should raise."""
        der = b"\x04\x40" + b"\x00" * 64
        with pytest.raises(ChallengeError, match="expected 32-byte SHA-256 digest"):
            _parse_acme_identifier_extension(der)


# ---------------------------------------------------------------------------
# Helper to build a mock x509 certificate with configurable extensions
# ---------------------------------------------------------------------------


def _make_mock_cert(
    *,
    san_dns: list[str] | None = None,
    san_ips: list[str] | None = None,
    has_san: bool = True,
    acme_ext_der: bytes | None = None,
    acme_ext_critical: bool = True,
    has_acme_ext: bool = True,
):
    """Build a mock cryptography x509 certificate object."""
    cert = MagicMock(spec=x509.Certificate)

    # Build extensions collection
    extensions = MagicMock()

    # SAN extension
    if has_san:
        san_ext = MagicMock()
        san_value = MagicMock(spec=x509.SubjectAlternativeName)

        dns_names = san_dns or []
        san_value.get_values_for_type.side_effect = lambda t: (
            dns_names
            if t is x509.DNSName
            else [ipaddress.ip_address(ip) for ip in (san_ips or [])]
            if t is x509.IPAddress
            else []
        )
        san_ext.value = san_value

        def get_ext_for_class(cls):
            if cls is x509.SubjectAlternativeName:
                return san_ext
            raise x509.ExtensionNotFound(
                f"No {cls} extension",
                ObjectIdentifier("1.2.3.4"),
            )

        extensions.get_extension_for_class = get_ext_for_class
    else:

        def get_ext_for_class_no_san(cls):
            raise x509.ExtensionNotFound(
                f"No {cls} extension",
                ObjectIdentifier("1.2.3.4"),
            )

        extensions.get_extension_for_class = get_ext_for_class_no_san

    # acmeIdentifier extension
    if has_acme_ext:
        acme_ext = MagicMock()
        acme_ext.critical = acme_ext_critical
        acme_ext_value = MagicMock()
        acme_ext_value.value = acme_ext_der
        acme_ext.value = acme_ext_value

        def get_ext_for_oid(oid):
            if oid == _ACME_IDENTIFIER_OID:
                return acme_ext
            raise x509.ExtensionNotFound(
                f"No {oid} extension",
                oid,
            )

        extensions.get_extension_for_oid = get_ext_for_oid
    else:

        def get_ext_for_oid_no_acme(oid):
            raise x509.ExtensionNotFound(
                f"No {oid} extension",
                oid,
            )

        extensions.get_extension_for_oid = get_ext_for_oid_no_acme

    cert.extensions = extensions
    return cert


# ---------------------------------------------------------------------------
# TlsAlpn01Validator.validate
# ---------------------------------------------------------------------------


class TestTlsAlpn01Validator:
    """Tests for the TLS-ALPN-01 validate method."""

    TOKEN = "test-token-abc"
    JWK = {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}
    KEY_AUTHZ = "test-token-abc.thumbprint123"

    @pytest.fixture(autouse=True)
    def _patch_key_authorization(self):
        with patch(
            "acmeeh.challenge.tls_alpn01.key_authorization",
            return_value=self.KEY_AUTHZ,
        ):
            yield

    @property
    def expected_digest(self) -> bytes:
        return hashlib.sha256(self.KEY_AUTHZ.encode("ascii")).digest()

    def _valid_acme_ext_der(self) -> bytes:
        """Return valid DER for the acmeIdentifier extension."""
        return b"\x04\x20" + self.expected_digest

    def _make_tls_context(
        self,
        *,
        negotiated_alpn: str | None = _ACME_TLS_ALPN,
        der_cert: bytes | None = b"FAKE_DER",
    ):
        """Create mock socket and TLS socket context managers."""
        mock_tls_sock = MagicMock()
        mock_tls_sock.selected_alpn_protocol.return_value = negotiated_alpn
        mock_tls_sock.getpeercert.return_value = der_cert
        mock_tls_sock.__enter__ = MagicMock(return_value=mock_tls_sock)
        mock_tls_sock.__exit__ = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        return mock_sock, mock_tls_sock

    @patch("acmeeh.challenge.tls_alpn01.x509.load_der_x509_certificate")
    @patch("acmeeh.challenge.tls_alpn01.ssl.SSLContext")
    @patch("acmeeh.challenge.tls_alpn01.socket.create_connection")
    def test_successful_dns_validation(
        self,
        mock_create_conn,
        mock_ssl_ctx_cls,
        mock_load_cert,
    ):
        """Successful TLS-ALPN-01 validation for a DNS identifier."""
        mock_sock, mock_tls_sock = self._make_tls_context()
        mock_create_conn.return_value = mock_sock

        ctx_instance = MagicMock()
        mock_ssl_ctx_cls.return_value = ctx_instance
        ctx_instance.wrap_socket.return_value = mock_tls_sock

        cert = _make_mock_cert(
            san_dns=["example.com"],
            acme_ext_der=self._valid_acme_ext_der(),
            acme_ext_critical=True,
        )
        mock_load_cert.return_value = cert

        validator = TlsAlpn01Validator(settings=None)
        # Should not raise
        validator.validate(
            token=self.TOKEN,
            jwk=self.JWK,
            identifier_type="dns",
            identifier_value="example.com",
        )

        # Verify SNI was set to the domain name
        ctx_instance.wrap_socket.assert_called_once_with(
            mock_sock,
            server_hostname="example.com",
        )

    @patch("acmeeh.challenge.tls_alpn01.x509.load_der_x509_certificate")
    @patch("acmeeh.challenge.tls_alpn01.ssl.SSLContext")
    @patch("acmeeh.challenge.tls_alpn01.socket.create_connection")
    def test_successful_ip_validation(
        self,
        mock_create_conn,
        mock_ssl_ctx_cls,
        mock_load_cert,
    ):
        """Successful TLS-ALPN-01 validation for an IP identifier (SNI=None)."""
        mock_sock, mock_tls_sock = self._make_tls_context()
        mock_create_conn.return_value = mock_sock

        ctx_instance = MagicMock()
        mock_ssl_ctx_cls.return_value = ctx_instance
        ctx_instance.wrap_socket.return_value = mock_tls_sock

        cert = _make_mock_cert(
            san_ips=["192.0.2.1"],
            acme_ext_der=self._valid_acme_ext_der(),
            acme_ext_critical=True,
        )
        mock_load_cert.return_value = cert

        validator = TlsAlpn01Validator(settings=None)
        validator.validate(
            token=self.TOKEN,
            jwk=self.JWK,
            identifier_type="ip",
            identifier_value="192.0.2.1",
        )

        # For IP identifiers, server_hostname should be None
        ctx_instance.wrap_socket.assert_called_once_with(
            mock_sock,
            server_hostname=None,
        )

    @patch("acmeeh.challenge.tls_alpn01.ssl.SSLContext")
    @patch("acmeeh.challenge.tls_alpn01.socket.create_connection")
    def test_alpn_negotiation_failure(
        self,
        mock_create_conn,
        mock_ssl_ctx_cls,
    ):
        """ALPN negotiation returns wrong protocol -> ChallengeError."""
        mock_sock, mock_tls_sock = self._make_tls_context(
            negotiated_alpn="h2",
        )
        mock_create_conn.return_value = mock_sock

        ctx_instance = MagicMock()
        mock_ssl_ctx_cls.return_value = ctx_instance
        ctx_instance.wrap_socket.return_value = mock_tls_sock

        validator = TlsAlpn01Validator(settings=None)
        with pytest.raises(ChallengeError, match="ALPN negotiation failed") as exc_info:
            validator.validate(
                token=self.TOKEN,
                jwk=self.JWK,
                identifier_type="dns",
                identifier_value="example.com",
            )
        assert exc_info.value.retryable is False

    @patch("acmeeh.challenge.tls_alpn01.ssl.SSLContext")
    @patch("acmeeh.challenge.tls_alpn01.socket.create_connection")
    def test_no_peer_certificate(
        self,
        mock_create_conn,
        mock_ssl_ctx_cls,
    ):
        """No peer certificate presented -> ChallengeError."""
        mock_sock, mock_tls_sock = self._make_tls_context(der_cert=None)
        mock_create_conn.return_value = mock_sock

        ctx_instance = MagicMock()
        mock_ssl_ctx_cls.return_value = ctx_instance
        ctx_instance.wrap_socket.return_value = mock_tls_sock

        validator = TlsAlpn01Validator(settings=None)
        with pytest.raises(ChallengeError, match="No peer certificate") as exc_info:
            validator.validate(
                token=self.TOKEN,
                jwk=self.JWK,
                identifier_type="dns",
                identifier_value="example.com",
            )
        assert exc_info.value.retryable is False

    @patch("acmeeh.challenge.tls_alpn01.ssl.SSLContext")
    @patch("acmeeh.challenge.tls_alpn01.socket.create_connection")
    def test_tls_connection_error_is_retryable(
        self,
        mock_create_conn,
        mock_ssl_ctx_cls,
    ):
        """TLS connection error (ssl.SSLError / OSError) -> retryable ChallengeError."""
        mock_create_conn.side_effect = ssl.SSLError("connection reset")

        ctx_instance = MagicMock()
        mock_ssl_ctx_cls.return_value = ctx_instance

        validator = TlsAlpn01Validator(settings=None)
        with pytest.raises(ChallengeError, match="TLS connection") as exc_info:
            validator.validate(
                token=self.TOKEN,
                jwk=self.JWK,
                identifier_type="dns",
                identifier_value="example.com",
            )
        assert exc_info.value.retryable is True

    @patch("acmeeh.challenge.tls_alpn01.x509.load_der_x509_certificate")
    @patch("acmeeh.challenge.tls_alpn01.ssl.SSLContext")
    @patch("acmeeh.challenge.tls_alpn01.socket.create_connection")
    def test_certificate_no_san(
        self,
        mock_create_conn,
        mock_ssl_ctx_cls,
        mock_load_cert,
    ):
        """Certificate without SAN extension -> ChallengeError."""
        mock_sock, mock_tls_sock = self._make_tls_context()
        mock_create_conn.return_value = mock_sock

        ctx_instance = MagicMock()
        mock_ssl_ctx_cls.return_value = ctx_instance
        ctx_instance.wrap_socket.return_value = mock_tls_sock

        cert = _make_mock_cert(has_san=False)
        mock_load_cert.return_value = cert

        validator = TlsAlpn01Validator(settings=None)
        with pytest.raises(ChallengeError, match="SubjectAlternativeName") as exc_info:
            validator.validate(
                token=self.TOKEN,
                jwk=self.JWK,
                identifier_type="dns",
                identifier_value="example.com",
            )
        assert exc_info.value.retryable is False

    @patch("acmeeh.challenge.tls_alpn01.x509.load_der_x509_certificate")
    @patch("acmeeh.challenge.tls_alpn01.ssl.SSLContext")
    @patch("acmeeh.challenge.tls_alpn01.socket.create_connection")
    def test_san_does_not_match(
        self,
        mock_create_conn,
        mock_ssl_ctx_cls,
        mock_load_cert,
    ):
        """SAN doesn't contain the identifier -> ChallengeError."""
        mock_sock, mock_tls_sock = self._make_tls_context()
        mock_create_conn.return_value = mock_sock

        ctx_instance = MagicMock()
        mock_ssl_ctx_cls.return_value = ctx_instance
        ctx_instance.wrap_socket.return_value = mock_tls_sock

        cert = _make_mock_cert(
            san_dns=["other.com"],
            acme_ext_der=self._valid_acme_ext_der(),
        )
        mock_load_cert.return_value = cert

        validator = TlsAlpn01Validator(settings=None)
        with pytest.raises(ChallengeError, match="SAN does not contain") as exc_info:
            validator.validate(
                token=self.TOKEN,
                jwk=self.JWK,
                identifier_type="dns",
                identifier_value="example.com",
            )
        assert exc_info.value.retryable is False

    @patch("acmeeh.challenge.tls_alpn01.x509.load_der_x509_certificate")
    @patch("acmeeh.challenge.tls_alpn01.ssl.SSLContext")
    @patch("acmeeh.challenge.tls_alpn01.socket.create_connection")
    def test_no_acme_identifier_extension(
        self,
        mock_create_conn,
        mock_ssl_ctx_cls,
        mock_load_cert,
    ):
        """Certificate lacks acmeIdentifier extension -> ChallengeError."""
        mock_sock, mock_tls_sock = self._make_tls_context()
        mock_create_conn.return_value = mock_sock

        ctx_instance = MagicMock()
        mock_ssl_ctx_cls.return_value = ctx_instance
        ctx_instance.wrap_socket.return_value = mock_tls_sock

        cert = _make_mock_cert(
            san_dns=["example.com"],
            has_acme_ext=False,
        )
        mock_load_cert.return_value = cert

        validator = TlsAlpn01Validator(settings=None)
        with pytest.raises(ChallengeError, match="acmeIdentifier extension") as exc_info:
            validator.validate(
                token=self.TOKEN,
                jwk=self.JWK,
                identifier_type="dns",
                identifier_value="example.com",
            )
        assert exc_info.value.retryable is False

    @patch("acmeeh.challenge.tls_alpn01.x509.load_der_x509_certificate")
    @patch("acmeeh.challenge.tls_alpn01.ssl.SSLContext")
    @patch("acmeeh.challenge.tls_alpn01.socket.create_connection")
    def test_acme_extension_not_critical(
        self,
        mock_create_conn,
        mock_ssl_ctx_cls,
        mock_load_cert,
    ):
        """acmeIdentifier extension not marked critical -> ChallengeError."""
        mock_sock, mock_tls_sock = self._make_tls_context()
        mock_create_conn.return_value = mock_sock

        ctx_instance = MagicMock()
        mock_ssl_ctx_cls.return_value = ctx_instance
        ctx_instance.wrap_socket.return_value = mock_tls_sock

        cert = _make_mock_cert(
            san_dns=["example.com"],
            acme_ext_der=self._valid_acme_ext_der(),
            acme_ext_critical=False,
        )
        mock_load_cert.return_value = cert

        validator = TlsAlpn01Validator(settings=None)
        with pytest.raises(ChallengeError, match="must be marked critical") as exc_info:
            validator.validate(
                token=self.TOKEN,
                jwk=self.JWK,
                identifier_type="dns",
                identifier_value="example.com",
            )
        assert exc_info.value.retryable is False

    @patch("acmeeh.challenge.tls_alpn01.x509.load_der_x509_certificate")
    @patch("acmeeh.challenge.tls_alpn01.ssl.SSLContext")
    @patch("acmeeh.challenge.tls_alpn01.socket.create_connection")
    def test_digest_mismatch(
        self,
        mock_create_conn,
        mock_ssl_ctx_cls,
        mock_load_cert,
    ):
        """acmeIdentifier digest doesn't match expected -> ChallengeError."""
        mock_sock, mock_tls_sock = self._make_tls_context()
        mock_create_conn.return_value = mock_sock

        ctx_instance = MagicMock()
        mock_ssl_ctx_cls.return_value = ctx_instance
        ctx_instance.wrap_socket.return_value = mock_tls_sock

        # Use a wrong digest
        wrong_digest = b"\x00" * 32
        wrong_der = b"\x04\x20" + wrong_digest

        cert = _make_mock_cert(
            san_dns=["example.com"],
            acme_ext_der=wrong_der,
            acme_ext_critical=True,
        )
        mock_load_cert.return_value = cert

        validator = TlsAlpn01Validator(settings=None)
        with pytest.raises(ChallengeError, match="digest does not match") as exc_info:
            validator.validate(
                token=self.TOKEN,
                jwk=self.JWK,
                identifier_type="dns",
                identifier_value="example.com",
            )
        assert exc_info.value.retryable is False

    def test_validator_challenge_type(self):
        """Verify the validator reports the correct challenge type."""
        v = TlsAlpn01Validator(settings=None)
        assert v.challenge_type == ChallengeType.TLS_ALPN_01

    def test_supported_identifier_types(self):
        """Validator supports both dns and ip identifiers."""
        v = TlsAlpn01Validator(settings=None)
        assert v.supports_identifier("dns")
        assert v.supports_identifier("ip")

    @patch("acmeeh.challenge.tls_alpn01.x509.load_der_x509_certificate")
    @patch("acmeeh.challenge.tls_alpn01.ssl.SSLContext")
    @patch("acmeeh.challenge.tls_alpn01.socket.create_connection")
    def test_custom_port_from_settings(
        self,
        mock_create_conn,
        mock_ssl_ctx_cls,
        mock_load_cert,
    ):
        """Validator uses port from settings."""
        mock_sock, mock_tls_sock = self._make_tls_context()
        mock_create_conn.return_value = mock_sock

        ctx_instance = MagicMock()
        mock_ssl_ctx_cls.return_value = ctx_instance
        ctx_instance.wrap_socket.return_value = mock_tls_sock

        cert = _make_mock_cert(
            san_dns=["example.com"],
            acme_ext_der=self._valid_acme_ext_der(),
            acme_ext_critical=True,
        )
        mock_load_cert.return_value = cert

        settings = SimpleNamespace(port=8443, timeout_seconds=5)
        validator = TlsAlpn01Validator(settings=settings)
        validator.validate(
            token=self.TOKEN,
            jwk=self.JWK,
            identifier_type="dns",
            identifier_value="example.com",
        )

        mock_create_conn.assert_called_once_with(
            ("example.com", 8443),
            timeout=5,
        )
