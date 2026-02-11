"""Integration tests for CRL generation."""

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acmeeh.config.settings import CrlSettings


def _make_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def test_crl_builds_empty():
    """CRL with no revoked certs should be valid DER."""
    from tests.integration.conftest import MockCertRepo

    from acmeeh.ca.crl import CRLManager

    cert, key = _make_ca()
    repo = MockCertRepo()
    settings = CrlSettings(
        enabled=True,
        path="/crl",
        rebuild_interval_seconds=3600,
        next_update_seconds=86400,
        hash_algorithm="sha256",
    )

    mgr = CRLManager(cert, key, repo, settings)
    crl_bytes = mgr.get_crl()

    assert len(crl_bytes) > 0
    # Should be valid DER
    crl = x509.load_der_x509_crl(crl_bytes)
    assert crl.issuer == cert.subject


def test_crl_caching():
    """Second call should return cached CRL."""
    from tests.integration.conftest import MockCertRepo

    from acmeeh.ca.crl import CRLManager

    cert, key = _make_ca()
    repo = MockCertRepo()
    settings = CrlSettings(
        enabled=True,
        path="/crl",
        rebuild_interval_seconds=3600,
        next_update_seconds=86400,
        hash_algorithm="sha256",
    )

    mgr = CRLManager(cert, key, repo, settings)
    crl1 = mgr.get_crl()
    crl2 = mgr.get_crl()
    assert crl1 is crl2  # Same object (cached)
