"""Tests for the CSR profile validator."""

from __future__ import annotations

from datetime import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from acmeeh.services.csr_validator import (
    _compute_public_key_fingerprint,
    _get_key_type_label,
    validate_csr_against_profile,
)

# ---------------------------------------------------------------------------
# Helpers to generate test CSRs
# ---------------------------------------------------------------------------


def _rsa_key(bits=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _ec_key(curve=None):
    if curve is None:
        curve = ec.SECP256R1()
    return ec.generate_private_key(curve)


def _build_csr(
    key=None,
    cn="example.com",
    sans=None,
    san_ips=None,
    key_usage=None,
    eku=None,
    hash_alg=None,
):
    """Build a CSR for testing.

    Parameters
    ----------
    key : private key, defaults to RSA 2048
    cn : common name or None for no CN
    sans : list of DNS names
    san_ips : list of IP strings
    key_usage : dict of KeyUsage kwargs
    eku : list of EKU OIDs
    hash_alg : hashing algorithm, defaults to SHA256
    """
    if key is None:
        key = _rsa_key()
    if hash_alg is None:
        hash_alg = hashes.SHA256()

    subject_attrs = []
    if cn is not None:
        subject_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))

    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(subject_attrs))

    # SAN extension
    san_names = []
    if sans:
        for s in sans:
            san_names.append(x509.DNSName(s))
    if san_ips:
        import ipaddress

        for ip_str in san_ips:
            san_names.append(x509.IPAddress(ipaddress.ip_address(ip_str)))
    if san_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_names),
            critical=False,
        )

    # Key usage extension
    if key_usage:
        defaults = {
            "digital_signature": False,
            "content_commitment": False,
            "key_encipherment": False,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        }
        defaults.update(key_usage)
        builder = builder.add_extension(
            x509.KeyUsage(**defaults),
            critical=True,
        )

    # EKU extension
    if eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(eku),
            critical=False,
        )

    return builder.sign(key, hash_alg)


# ---------------------------------------------------------------------------
# Stub certificate repo for key reuse / renewal window tests
# ---------------------------------------------------------------------------


class StubCertificateRepo:
    def __init__(self):
        self._by_fingerprint: dict[str, list] = {}
        self._by_hosts: list = []

    def add_cert_for_fingerprint(self, fingerprint: str, cert=None):
        self._by_fingerprint.setdefault(fingerprint, []).append(cert or "cert")

    def set_valid_certs_for_hosts(self, certs):
        self._by_hosts = certs

    def find_by_public_key_fingerprint(self, fingerprint: str) -> list:
        return self._by_fingerprint.get(fingerprint, [])

    def find_valid_certs_for_hosts(self, hosts: list[str], not_after_cutoff: datetime) -> list:
        return self._by_hosts


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestKeyType:
    def test_rsa_allowed(self):
        key = _rsa_key()
        csr = _build_csr(key=key, sans=["example.com"])
        profile = {"authorized_keys": {"RSA": 2048}}
        validate_csr_against_profile(csr, profile)  # should not raise

    def test_rsa_rejected(self):
        key = _rsa_key()
        csr = _build_csr(key=key, sans=["example.com"])
        profile = {"authorized_keys": {"EC.secp256r1": 0}}
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile)
        assert "Key type" in str(exc_info.value)

    def test_ec_allowed(self):
        key = _ec_key()
        csr = _build_csr(key=key, sans=["example.com"])
        profile = {"authorized_keys": {"EC.secp256r1": 0}}
        validate_csr_against_profile(csr, profile)

    def test_ec_rejected(self):
        key = _ec_key()
        csr = _build_csr(key=key, sans=["example.com"])
        profile = {"authorized_keys": {"RSA": 2048}}
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile)
        assert "Key type" in str(exc_info.value)


class TestKeySize:
    def test_rsa_too_small(self):
        key = _rsa_key(1024)
        csr = _build_csr(key=key, sans=["example.com"])
        profile = {"authorized_keys": {"RSA": 2048}}
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile)
        assert "Key size" in str(exc_info.value)

    def test_rsa_exact_minimum(self):
        key = _rsa_key(2048)
        csr = _build_csr(key=key, sans=["example.com"])
        profile = {"authorized_keys": {"RSA": 2048}}
        validate_csr_against_profile(csr, profile)

    def test_ec_no_minimum(self):
        key = _ec_key()
        csr = _build_csr(key=key, sans=["example.com"])
        profile = {"authorized_keys": {"EC.secp256r1": 0}}
        validate_csr_against_profile(csr, profile)


class TestSignatureAlgorithm:
    def test_sha256_rsa_allowed(self):
        csr = _build_csr(sans=["example.com"], hash_alg=hashes.SHA256())
        profile = {"authorized_signature_algorithms": ["SHA256withRSA"]}
        validate_csr_against_profile(csr, profile)

    def test_sha256_rsa_rejected(self):
        csr = _build_csr(sans=["example.com"], hash_alg=hashes.SHA256())
        profile = {"authorized_signature_algorithms": ["SHA384withRSA"]}
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile)
        assert "Signature algorithm" in str(exc_info.value)


class TestKeyUsage:
    def test_authorized_usage(self):
        csr = _build_csr(
            sans=["example.com"],
            key_usage={"digital_signature": True, "key_encipherment": True},
        )
        profile = {
            "authorized_key_usages": [
                "digital_signature",
                "key_encipherment",
                "content_commitment",
            ],
        }
        validate_csr_against_profile(csr, profile)

    def test_unauthorized_usage(self):
        csr = _build_csr(
            sans=["example.com"],
            key_usage={"digital_signature": True, "key_cert_sign": True},
        )
        profile = {"authorized_key_usages": ["digital_signature"]}
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile)
        assert "Key usages" in str(exc_info.value)

    def test_no_extension_passes(self):
        csr = _build_csr(sans=["example.com"])
        profile = {"authorized_key_usages": ["digital_signature"]}
        validate_csr_against_profile(csr, profile)  # no KU extension = passes


class TestExtendedKeyUsage:
    def test_authorized_eku(self):
        csr = _build_csr(
            sans=["example.com"],
            eku=[ExtendedKeyUsageOID.SERVER_AUTH],
        )
        profile = {"authorized_extended_key_usages": ["serverAuth", "clientAuth"]}
        validate_csr_against_profile(csr, profile)

    def test_unauthorized_eku(self):
        csr = _build_csr(
            sans=["example.com"],
            eku=[ExtendedKeyUsageOID.CODE_SIGNING],
        )
        profile = {"authorized_extended_key_usages": ["serverAuth"]}
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile)
        assert "Extended key usages" in str(exc_info.value)


class TestCommonName:
    def test_cn_minimum(self):
        csr = _build_csr(cn=None, sans=["example.com"])
        profile = {"common_name_minimum": 1}
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile)
        assert "CN(s)" in str(exc_info.value) and "minimum" in str(exc_info.value)

    def test_cn_maximum(self):
        csr = _build_csr(cn="example.com", sans=["example.com"])
        profile = {"common_name_maximum": 0}
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile)
        assert "CN(s)" in str(exc_info.value) and "maximum" in str(exc_info.value)

    def test_cn_regex_passes(self):
        csr = _build_csr(cn="web.corp.internal", sans=["web.corp.internal"])
        profile = {"common_name_regex": r".*\.corp\.internal"}
        validate_csr_against_profile(csr, profile)

    def test_cn_regex_fails(self):
        csr = _build_csr(cn="evil.external.com", sans=["evil.external.com"])
        profile = {"common_name_regex": r".*\.corp\.internal"}
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile)
        assert "does not match" in str(exc_info.value)

    def test_cn_count_no_constraint(self):
        """cn_minimum=-1 and cn_maximum=-1 means no constraint."""
        csr = _build_csr(cn="example.com", sans=["example.com"])
        profile = {"common_name_minimum": -1, "common_name_maximum": -1}
        validate_csr_against_profile(csr, profile)


class TestSAN:
    def test_san_minimum(self):
        csr = _build_csr(cn="example.com")  # no SANs
        profile = {"san_minimum": 1}
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile)
        assert "SAN(s)" in str(exc_info.value) and "minimum" in str(exc_info.value)

    def test_san_maximum(self):
        csr = _build_csr(cn="example.com", sans=["a.com", "b.com", "c.com"])
        profile = {"san_maximum": 2}
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile)
        assert "SAN(s)" in str(exc_info.value) and "maximum" in str(exc_info.value)

    def test_san_regex_passes(self):
        csr = _build_csr(sans=["web.corp.internal"])
        profile = {"san_regex": r".*\.corp\.internal"}
        validate_csr_against_profile(csr, profile)

    def test_san_regex_fails(self):
        csr = _build_csr(sans=["evil.external.com"])
        profile = {"san_regex": r".*\.corp\.internal"}
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile)
        assert "does not match" in str(exc_info.value)

    def test_san_types_allowed(self):
        csr = _build_csr(sans=["example.com"])
        profile = {"san_types": ["DNS_NAME", "IP_ADDRESS"]}
        validate_csr_against_profile(csr, profile)

    def test_san_types_rejected(self):
        csr = _build_csr(san_ips=["10.0.0.1"])
        profile = {"san_types": ["DNS_NAME"]}
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile)
        assert "SAN type" in str(exc_info.value)


class TestSubjectRegex:
    def test_subject_passes(self):
        csr = _build_csr(cn="web.corp.internal", sans=["web.corp.internal"])
        profile = {"subject_regex": r"CN=.*\.corp\.internal"}
        validate_csr_against_profile(csr, profile)

    def test_subject_fails(self):
        csr = _build_csr(cn="evil.external.com", sans=["evil.external.com"])
        profile = {"subject_regex": r"CN=.*\.corp\.internal"}
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile)
        assert "Subject" in str(exc_info.value) and "does not match" in str(exc_info.value)


class TestWildcard:
    def test_wildcard_cn_allowed(self):
        csr = _build_csr(cn="*.example.com", sans=["*.example.com"])
        profile = {"wildcard_in_common_name": True}
        validate_csr_against_profile(csr, profile)

    def test_wildcard_cn_rejected(self):
        csr = _build_csr(cn="*.example.com", sans=["*.example.com"])
        profile = {"wildcard_in_common_name": False}
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile)
        assert "Wildcard CN" in str(exc_info.value)

    def test_wildcard_san_allowed(self):
        csr = _build_csr(sans=["*.example.com"])
        profile = {"wildcard_in_san": True}
        validate_csr_against_profile(csr, profile)

    def test_wildcard_san_rejected(self):
        csr = _build_csr(sans=["*.example.com"])
        profile = {"wildcard_in_san": False}
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile)
        assert "Wildcard SAN" in str(exc_info.value)

    def test_non_wildcard_passes_wildcard_false(self):
        csr = _build_csr(cn="example.com", sans=["example.com"])
        profile = {"wildcard_in_common_name": False, "wildcard_in_san": False}
        validate_csr_against_profile(csr, profile)


class TestKeyReuse:
    def test_reuse_allowed_by_default(self):
        """No reuse_key field means no check."""
        csr = _build_csr(sans=["example.com"])
        profile = {}
        validate_csr_against_profile(csr, profile)

    def test_reuse_allowed_when_true(self):
        csr = _build_csr(sans=["example.com"])
        repo = StubCertificateRepo()
        fp = _compute_public_key_fingerprint(csr.public_key())
        repo.add_cert_for_fingerprint(fp)
        profile = {"reuse_key": True}
        validate_csr_against_profile(csr, profile, certificate_repo=repo)

    def test_reuse_rejected(self):
        key = _rsa_key()
        csr = _build_csr(key=key, sans=["example.com"])
        repo = StubCertificateRepo()
        fp = _compute_public_key_fingerprint(key.public_key())
        repo.add_cert_for_fingerprint(fp)
        profile = {"reuse_key": False}
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile, certificate_repo=repo)
        assert "Key reuse" in str(exc_info.value)

    def test_reuse_ok_when_no_existing(self):
        csr = _build_csr(sans=["example.com"])
        repo = StubCertificateRepo()
        profile = {"reuse_key": False}
        validate_csr_against_profile(csr, profile, certificate_repo=repo)


class TestRenewalWindow:
    def test_renewal_blocked(self):
        csr = _build_csr(sans=["example.com"])
        repo = StubCertificateRepo()
        repo.set_valid_certs_for_hosts(["existing-cert"])
        profile = {"renewal_window_days": 30}
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile, certificate_repo=repo)
        assert "Renewal" in str(exc_info.value)

    def test_renewal_allowed_when_no_active(self):
        csr = _build_csr(sans=["example.com"])
        repo = StubCertificateRepo()
        repo.set_valid_certs_for_hosts([])
        profile = {"renewal_window_days": 30}
        validate_csr_against_profile(csr, profile, certificate_repo=repo)

    def test_renewal_no_check_when_zero(self):
        csr = _build_csr(sans=["example.com"])
        profile = {"renewal_window_days": 0}
        validate_csr_against_profile(csr, profile)


class TestSubdomainDepth:
    """Tests for max_subdomain_depth / depth_base_domains validation."""

    def test_depth_allowed(self):
        """sub.example.com depth 1, max_depth=1 → passes."""
        csr = _build_csr(cn="sub.example.com", sans=["sub.example.com"])
        profile = {
            "max_subdomain_depth": 1,
            "depth_base_domains": ["example.com"],
        }
        validate_csr_against_profile(csr, profile)

    def test_depth_exceeded(self):
        """a.b.example.com depth 2, max_depth=1 → rejected."""
        csr = _build_csr(cn="a.b.example.com", sans=["a.b.example.com"])
        profile = {
            "max_subdomain_depth": 1,
            "depth_base_domains": ["example.com"],
        }
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile)
        assert "subdomain depth 2" in str(exc_info.value)
        assert "exceeds maximum allowed depth 1" in str(exc_info.value)

    def test_depth_exact_base(self):
        """example.com depth 0, max_depth=0 → passes."""
        csr = _build_csr(cn="example.com", sans=["example.com"])
        profile = {
            "max_subdomain_depth": 0,
            "depth_base_domains": ["example.com"],
        }
        validate_csr_against_profile(csr, profile)

    def test_depth_no_base_match(self):
        """evil.other.com with base example.com → rejected."""
        csr = _build_csr(cn="evil.other.com", sans=["evil.other.com"])
        profile = {
            "max_subdomain_depth": 5,
            "depth_base_domains": ["example.com"],
        }
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile)
        assert "does not match any configured base domain" in str(exc_info.value)

    def test_depth_wildcard_counts(self):
        """*.example.com depth=1, max_depth=1 → passes.
        *.sub.example.com depth=2, max_depth=1 → rejected."""
        csr_ok = _build_csr(sans=["*.example.com"])
        profile = {
            "max_subdomain_depth": 1,
            "depth_base_domains": ["example.com"],
        }
        validate_csr_against_profile(csr_ok, profile)

        csr_bad = _build_csr(sans=["*.sub.example.com"])
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr_bad, profile)
        assert "subdomain depth 2" in str(exc_info.value)

    def test_depth_multiple_bases(self):
        """Matches the longest base domain."""
        csr = _build_csr(cn="app.corp.internal", sans=["app.corp.internal"])
        profile = {
            "max_subdomain_depth": 1,
            "depth_base_domains": ["internal", "corp.internal"],
        }
        # With base "corp.internal", depth = 1 → allowed.
        # (With base "internal", depth would be 2 → rejected.)
        validate_csr_against_profile(csr, profile)

    def test_depth_cn_checked(self):
        """CN is also subject to depth check."""
        csr = _build_csr(cn="a.b.example.com", sans=["ok.example.com"])
        profile = {
            "max_subdomain_depth": 1,
            "depth_base_domains": ["example.com"],
        }
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile)
        assert "a.b.example.com" in str(exc_info.value)

    def test_depth_not_checked_when_omitted(self):
        """No max_subdomain_depth → no depth checking at all."""
        csr = _build_csr(sans=["a.b.c.d.example.com"])
        profile = {}
        validate_csr_against_profile(csr, profile)

    def test_depth_ip_san_skipped(self):
        """IP SANs are not subject to depth checks."""
        csr = _build_csr(san_ips=["10.0.0.1"], sans=["ok.example.com"])
        profile = {
            "max_subdomain_depth": 1,
            "depth_base_domains": ["example.com"],
        }
        validate_csr_against_profile(csr, profile)


class TestMultipleViolations:
    def test_all_violations_reported(self):
        """Verify that multiple violations are collected and reported together."""
        key = _rsa_key(1024)
        csr = _build_csr(
            key=key,
            cn="*.evil.com",
            sans=["*.evil.com", "another.evil.com"],
        )
        profile = {
            "authorized_keys": {"RSA": 2048},
            "wildcard_in_common_name": False,
            "wildcard_in_san": False,
            "san_maximum": 1,
        }
        with pytest.raises(Exception) as exc_info:
            validate_csr_against_profile(csr, profile)
        detail = str(exc_info.value)
        # All of these should be present in the combined error
        assert "Key size" in detail
        assert "Wildcard CN" in detail
        assert "Wildcard SAN" in detail
        assert "SAN(s)" in detail


class TestEmptyProfile:
    def test_empty_profile_allows_everything(self):
        """An empty profile_data dict means no constraints."""
        csr = _build_csr(
            cn="*.whatever.com",
            sans=["*.whatever.com", "a.com", "b.com"],
        )
        validate_csr_against_profile(csr, {})


class TestHelperFunctions:
    def test_key_type_label_rsa(self):
        key = _rsa_key()
        assert _get_key_type_label(key.public_key()) == "RSA"

    def test_key_type_label_ec(self):
        key = _ec_key()
        assert _get_key_type_label(key.public_key()) == "EC.secp256r1"

    def test_key_type_label_ec_384(self):
        key = _ec_key(ec.SECP384R1())
        assert _get_key_type_label(key.public_key()) == "EC.secp384r1"

    def test_fingerprint_deterministic(self):
        key = _rsa_key()
        fp1 = _compute_public_key_fingerprint(key.public_key())
        fp2 = _compute_public_key_fingerprint(key.public_key())
        assert fp1 == fp2
        assert len(fp1) == 64  # SHA-256 hex
