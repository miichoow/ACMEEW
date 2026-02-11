"""Tests covering uncovered lines in core/jws.py and services/csr_validator.py."""

import base64
import json
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from acmeeh.app.errors import MALFORMED, AcmeProblem
from acmeeh.core.jws import jwk_to_public_key, parse_jws, validate_eab_jws, verify_signature
from acmeeh.services.csr_validator import (
    _check_extended_key_usages,
    _check_renewal_window,
    _check_san_constraints,
    _get_key_size,
    _get_key_type_label,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64(data: bytes) -> str:
    """URL-safe base64 encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_jws_body(alg="RS256", payload=b"", extra_protected=None):
    """Build a raw JWS JSON body (bytes) with the given algorithm."""
    protected = {"alg": alg}
    if extra_protected:
        protected.update(extra_protected)
    body_dict = {
        "protected": _b64(json.dumps(protected).encode()),
        "payload": _b64(payload) if payload else "",
        "signature": _b64(b"fakesignature"),
    }
    return json.dumps(body_dict).encode()


# ===================================================================
# core/jws.py -- parse_jws re-raise branches (lines 221, 238-242, 247-251)
# ===================================================================


class TestParseJwsReraise:
    """Cover the 'except AcmeProblem: raise' branches in parse_jws."""

    def test_protected_decode_reraises_acme_problem(self):
        """Line ~221: _b64url_decode raises AcmeProblem during protected decode."""
        body = _make_jws_body()
        with patch(
            "acmeeh.core.jws._b64url_decode",
            side_effect=AcmeProblem(MALFORMED, "bad protected b64"),
        ):
            with pytest.raises(AcmeProblem, match="bad protected b64"):
                parse_jws(body)

    def test_payload_decode_reraises_acme_problem(self):
        """Lines ~238-242: _b64url_decode raises AcmeProblem during payload decode."""
        body = _make_jws_body(payload=b'{"foo": "bar"}')
        calls = []

        def selective_decode(s):
            calls.append(s)
            if len(calls) == 1:
                # First call: protected header -- return valid JSON bytes
                return json.dumps({"alg": "RS256"}).encode()
            # Second call: payload -- raise
            raise AcmeProblem(MALFORMED, "payload b64 fail")

        with patch("acmeeh.core.jws._b64url_decode", side_effect=selective_decode):
            with pytest.raises(AcmeProblem, match="payload b64 fail"):
                parse_jws(body)

    def test_signature_decode_reraises_acme_problem(self):
        """Lines ~247-251: _b64url_decode raises AcmeProblem during signature decode."""
        body = _make_jws_body(payload=b'{"foo": "bar"}')
        calls = []

        def selective_decode(s):
            calls.append(s)
            if len(calls) == 1:
                return json.dumps({"alg": "RS256"}).encode()
            if len(calls) == 2:
                return b'{"foo": "bar"}'
            raise AcmeProblem(MALFORMED, "sig b64 fail")

        with patch("acmeeh.core.jws._b64url_decode", side_effect=selective_decode):
            with pytest.raises(AcmeProblem, match="sig b64 fail"):
                parse_jws(body)


# ===================================================================
# core/jws.py -- jwk_to_public_key re-raise branches (lines 523, 565)
# ===================================================================


class TestJwkToPublicKeyReraise:
    """Cover except AcmeProblem: raise in _jwk_to_rsa / _jwk_to_ec."""

    def test_rsa_jwk_decode_reraises_acme_problem(self):
        """Line ~523: _b64url_decode raises AcmeProblem in RSA JWK decode."""
        with patch(
            "acmeeh.core.jws._b64url_decode",
            side_effect=AcmeProblem(MALFORMED, "rsa b64 decode"),
        ):
            with pytest.raises(AcmeProblem, match="rsa b64 decode"):
                jwk_to_public_key({"kty": "RSA", "n": "xx", "e": "yy"})

    def test_ec_jwk_decode_reraises_acme_problem(self):
        """Line ~565: _b64url_decode raises AcmeProblem in EC JWK decode."""
        with patch(
            "acmeeh.core.jws._b64url_decode",
            side_effect=AcmeProblem(MALFORMED, "ec b64 decode"),
        ):
            with pytest.raises(AcmeProblem, match="ec b64 decode"):
                jwk_to_public_key({"kty": "EC", "crv": "P-256", "x": "aa", "y": "bb"})


# ===================================================================
# core/jws.py -- unsupported algorithm in verify_signature (lines 712-713)
# ===================================================================


class TestVerifySignatureUnsupportedAlgorithm:
    """Cover lines 712-713: unsupported algorithm branch."""

    def test_unsupported_algorithm_eddsa_raises(self):
        """verify_signature raises AcmeProblem for unsupported algorithm EdDSA."""
        body = _make_jws_body(alg="EdDSA")
        jws = parse_jws(body)
        mock_key = MagicMock()

        with pytest.raises(AcmeProblem, match="[Uu]nsupported algorithm"):
            verify_signature(jws, mock_key)

    def test_unsupported_algorithm_none_raises(self):
        """verify_signature raises for 'none' algorithm."""
        body = _make_jws_body(alg="none")
        jws = parse_jws(body)
        mock_key = MagicMock()

        with pytest.raises(AcmeProblem):
            verify_signature(jws, mock_key)

    def test_unsupported_algorithm_hs256_raises(self):
        """verify_signature raises for symmetric algorithm HS256."""
        body = _make_jws_body(alg="HS256")
        jws = parse_jws(body)
        mock_key = MagicMock()

        with pytest.raises(AcmeProblem):
            verify_signature(jws, mock_key)


# ===================================================================
# core/jws.py -- validate_eab_jws re-raise branches (lines 919-920, 946-947, 979-980)
# ===================================================================


class TestValidateEabJwsReraise:
    """Cover except AcmeProblem: raise branches in validate_eab_jws."""

    @staticmethod
    def _eab_dict():
        return {
            "protected": _b64(json.dumps({"alg": "HS256", "kid": "kid1"}).encode()),
            "payload": _b64(json.dumps({"kty": "EC"}).encode()),
            "signature": _b64(b"fakedhmac"),
        }

    @staticmethod
    def _outer_jwk():
        return {"kty": "EC"}

    def test_eab_protected_decode_reraises(self):
        """Lines 919-920: _b64url_decode raises AcmeProblem on protected decode."""
        with patch(
            "acmeeh.core.jws._b64url_decode",
            side_effect=AcmeProblem(MALFORMED, "eab header fail"),
        ):
            with pytest.raises(AcmeProblem, match="eab header fail"):
                validate_eab_jws(self._eab_dict(), self._outer_jwk(), "aGVsbG8=")

    def test_eab_payload_decode_reraises(self):
        """Lines 946-947: _b64url_decode raises AcmeProblem on payload decode."""
        calls = []

        def selective(s):
            calls.append(s)
            if len(calls) == 1:
                return json.dumps({"alg": "HS256", "kid": "kid1"}).encode()
            raise AcmeProblem(MALFORMED, "eab payload fail")

        with patch("acmeeh.core.jws._b64url_decode", side_effect=selective):
            with pytest.raises(AcmeProblem, match="eab payload fail"):
                validate_eab_jws(self._eab_dict(), self._outer_jwk(), "aGVsbG8=")

    def test_eab_signature_decode_reraises(self):
        """Lines 979-980: _b64url_decode raises AcmeProblem on sig decode."""
        outer_jwk = {"kty": "EC"}
        calls = []

        original_b64url_decode = None

        def selective(s):
            calls.append(s)
            if len(calls) == 1:
                # protected header
                return json.dumps({"alg": "HS256", "kid": "kid1"}).encode()
            if len(calls) == 2:
                # payload -- must match outer_jwk
                return json.dumps(outer_jwk).encode()
            if len(calls) == 3:
                # hmac key (line 969, outside try block)
                return b"secret_key_bytes_32_long_enough!"
            # signature decode (line 978, inside try block)
            raise AcmeProblem(MALFORMED, "eab sig fail")

        with patch("acmeeh.core.jws._b64url_decode", side_effect=selective):
            with pytest.raises(AcmeProblem, match="eab sig fail"):
                validate_eab_jws(self._eab_dict(), outer_jwk, "aGVsbG8=")


# ===================================================================
# services/csr_validator.py -- _get_key_type_label (lines 84-88)
# ===================================================================


class TestGetKeyTypeLabel:
    """Cover lines 84-88: Ed25519, Ed448, and unknown key types."""

    def test_ed25519_key_type(self):
        key = ed25519.Ed25519PrivateKey.generate().public_key()
        assert _get_key_type_label(key) == "Ed25519"

    def test_ed448_key_type(self):
        key = ed448.Ed448PrivateKey.generate().public_key()
        assert _get_key_type_label(key) == "Ed448"

    def test_unknown_key_type_returns_class_name(self):
        """Line 88: fall-through returns type().__name__."""
        mock_key = MagicMock(spec=[])
        result = _get_key_type_label(mock_key)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_rsa_key_type(self):
        key = rsa.generate_private_key(65537, 2048).public_key()
        assert _get_key_type_label(key) == "RSA"

    def test_ec_key_type_secp256r1(self):
        key = ec.generate_private_key(ec.SECP256R1()).public_key()
        assert _get_key_type_label(key) == "EC.secp256r1"


# ===================================================================
# services/csr_validator.py -- _get_key_size (lines 95-97)
# ===================================================================


class TestGetKeySize:
    """Cover lines 95-97: EC key size and unknown key type returns None."""

    def test_ec_key_size_256(self):
        key = ec.generate_private_key(ec.SECP256R1()).public_key()
        assert _get_key_size(key) == 256

    def test_ec_key_size_384(self):
        key = ec.generate_private_key(ec.SECP384R1()).public_key()
        assert _get_key_size(key) == 384

    def test_unknown_key_returns_none(self):
        """Line 97: non-RSA/non-EC key returns None."""
        key = ed25519.Ed25519PrivateKey.generate().public_key()
        assert _get_key_size(key) is None

    def test_rsa_key_size(self):
        key = rsa.generate_private_key(65537, 2048).public_key()
        assert _get_key_size(key) == 2048


# ===================================================================
# services/csr_validator.py -- _check_san_constraints (lines 395, 400, 413)
# ===================================================================


class TestCheckSanConstraints:
    """Cover lines 394-395, 399-400, 412-413: null byte, control char, duplicate SAN."""

    @staticmethod
    def _build_csr(cn="test.example.com", sans=None):
        """Build a simple CSR for test use."""
        key = ec.generate_private_key(ec.SECP256R1())
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, cn),
                ]
            )
        )
        if sans:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(sans),
                critical=False,
            )
        return builder.sign(key, hashes.SHA256())

    def test_null_byte_in_san(self):
        """Line 395: SAN value containing a null byte."""
        violations = []
        csr = self._build_csr()
        san_pairs = [("DNS_NAME", "test\x00.example.com")]
        _check_san_constraints({}, csr, san_pairs, violations)
        assert any("null" in v.lower() for v in violations)

    def test_control_char_in_san(self):
        """Line 400: SAN value containing control characters."""
        violations = []
        csr = self._build_csr()
        san_pairs = [("DNS_NAME", "test\x01.example.com")]
        _check_san_constraints({}, csr, san_pairs, violations)
        assert any("control" in v.lower() for v in violations)

    def test_duplicate_san(self):
        """Line 413: duplicate SAN entry."""
        violations = []
        csr = self._build_csr()
        san_pairs = [("DNS_NAME", "example.com"), ("DNS_NAME", "example.com")]
        _check_san_constraints({}, csr, san_pairs, violations)
        assert any("duplicate" in v.lower() for v in violations)

    def test_valid_san_no_violations(self):
        """Sanity check: valid SANs produce no content-related violations."""
        violations = []
        csr = self._build_csr()
        san_pairs = [("DNS_NAME", "example.com"), ("DNS_NAME", "www.example.com")]
        _check_san_constraints({}, csr, san_pairs, violations)
        relevant = [
            v for v in violations if any(kw in v.lower() for kw in ("null", "control", "duplicate"))
        ]
        assert relevant == []

    def test_null_byte_takes_precedence_over_control_char(self):
        """Null byte triggers the null byte branch (elif means control chars
        are not reported for the same SAN)."""
        violations = []
        csr = self._build_csr()
        san_pairs = [("DNS_NAME", "test\x00\x01.example.com")]
        _check_san_constraints({}, csr, san_pairs, violations)
        # Should report null byte, not control characters
        assert any("null" in v.lower() for v in violations)
        assert not any("control" in v.lower() for v in violations)


# ===================================================================
# services/csr_validator.py -- _check_renewal_window (line 546)
# ===================================================================


class TestCheckRenewalWindow:
    """Cover line 546: early return when no DNS hosts found."""

    def test_no_san_pairs_returns_early(self):
        """Line 546: empty san_pairs causes early return."""
        violations = []
        profile = {"renewal_window_days": 30}
        mock_repo = MagicMock()
        _check_renewal_window(profile, [], mock_repo, violations)
        assert violations == []
        # Repository should not be called since we return early
        mock_repo.find_valid_certs_for_hosts.assert_not_called()

    def test_only_ip_sans_returns_early(self):
        """Line 546: only IP SANs (no DNS_NAME) causes early return."""
        violations = []
        profile = {"renewal_window_days": 30}
        mock_repo = MagicMock()
        _check_renewal_window(profile, [("IP_ADDRESS", "1.2.3.4")], mock_repo, violations)
        assert violations == []
        mock_repo.find_valid_certs_for_hosts.assert_not_called()

    def test_zero_renewal_days_returns_early(self):
        """Renewal_window_days <= 0 means the check is disabled."""
        violations = []
        profile = {"renewal_window_days": 0}
        mock_repo = MagicMock()
        _check_renewal_window(profile, [("DNS_NAME", "example.com")], mock_repo, violations)
        assert violations == []
        mock_repo.find_valid_certs_for_hosts.assert_not_called()

    def test_none_repo_returns_early(self):
        """No certificate_repo means the check is disabled."""
        violations = []
        profile = {"renewal_window_days": 30}
        _check_renewal_window(profile, [("DNS_NAME", "example.com")], None, violations)
        assert violations == []


# ===================================================================
# services/csr_validator.py -- _check_extended_key_usages (lines 351-352)
# ===================================================================


class TestCheckExtendedKeyUsages:
    """Cover lines 351-352: CSR without EKU extension hits ExtensionNotFound."""

    def test_csr_without_eku_no_violation(self):
        """CSR without EKU, profile with authorized_extended_key_usages.
        Lines 351-352: ExtensionNotFound is caught, no violation added."""
        key = ec.generate_private_key(ec.SECP256R1())
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
                ]
            )
        )
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("test.example.com")]),
            critical=False,
        )
        # No EKU extension
        csr = builder.sign(key, hashes.SHA256())

        violations = []
        profile_data = {"authorized_extended_key_usages": ["serverAuth", "clientAuth"]}
        _check_extended_key_usages(profile_data, csr, violations)
        # ExtensionNotFound was caught; no violations
        assert violations == []

    def test_no_authorized_eku_in_profile_returns_early(self):
        """When profile has no authorized_extended_key_usages, skip check."""
        key = ec.generate_private_key(ec.SECP256R1())
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
                ]
            )
        )
        csr = builder.sign(key, hashes.SHA256())

        violations = []
        _check_extended_key_usages({}, csr, violations)
        assert violations == []
