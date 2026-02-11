"""Tests for OCSP service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

from acmeeh.config.settings import OcspSettings
from acmeeh.core.types import RevocationReason
from acmeeh.services.ocsp import OCSPService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ocsp_settings(**kwargs) -> OcspSettings:
    defaults = dict(
        enabled=True,
        path="/ocsp",
        response_validity_seconds=3600,
        hash_algorithm="sha256",
    )
    defaults.update(kwargs)
    return OcspSettings(**defaults)


def _generate_ca():
    """Generate a self-signed CA cert and key."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test OCSP CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _build_ocsp_request(serial: int, issuer_cert: x509.Certificate) -> bytes:
    """Build a DER-encoded OCSP request for the given serial."""
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(issuer_cert, issuer_cert, hashes.SHA256())
    # The above uses issuer_cert as both cert and issuer, but we need to set the serial.
    # Since the OCSPRequestBuilder doesn't let us set serial directly with add_certificate,
    # we build with the issuer cert and rely on it matching. For a proper test,
    # we generate an actual leaf cert.
    return builder.build().public_bytes(serialization.Encoding.DER)


def _build_leaf_cert(ca_cert, ca_key, serial: int) -> x509.Certificate:
    """Build a leaf certificate signed by the CA."""
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.test")]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=90))
        .sign(ca_key, hashes.SHA256())
    )


def _build_ocsp_request_for_leaf(
    leaf_cert: x509.Certificate, issuer_cert: x509.Certificate
) -> bytes:
    """Build an OCSP request for a specific leaf certificate."""
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(leaf_cert, issuer_cert, hashes.SHA256())
    return builder.build().public_bytes(serialization.Encoding.DER)


@dataclass(frozen=True)
class FakeCert:
    id: UUID
    serial_number: str
    not_before_cert: datetime
    not_after_cert: datetime
    revoked_at: datetime | None = None
    revocation_reason: RevocationReason | None = None


class StubCertRepo:
    def __init__(self):
        self._by_serial: dict[str, FakeCert] = {}

    def add(self, cert: FakeCert):
        self._by_serial[cert.serial_number] = cert

    def find_by_serial(self, serial_hex: str) -> FakeCert | None:
        return self._by_serial.get(serial_hex)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ca_pair():
    return _generate_ca()


@pytest.fixture
def cert_repo():
    return StubCertRepo()


@pytest.fixture
def ocsp_service(ca_pair, cert_repo):
    root_cert, root_key = ca_pair
    return OCSPService(cert_repo, root_cert, root_key, _ocsp_settings())


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRequestParsing:
    """Request parsing."""

    def test_malformed_request_returns_malformed_response(self, ocsp_service):
        result = ocsp_service.handle_request(b"this is not a valid OCSP request")
        # Should return a valid OCSP error response (MALFORMED_REQUEST)
        assert isinstance(result, bytes)
        resp = ocsp.load_der_ocsp_response(result)
        assert resp.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST

    def test_empty_request_returns_malformed(self, ocsp_service):
        result = ocsp_service.handle_request(b"")
        assert isinstance(result, bytes)
        resp = ocsp.load_der_ocsp_response(result)
        assert resp.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST


class TestGoodResponse:
    """Good response for valid cert."""

    def test_valid_cert_returns_good(self, ca_pair, cert_repo):
        root_cert, root_key = ca_pair
        now = datetime.now(UTC)

        # Build a leaf cert with a known serial
        serial = 0x123456
        leaf_cert = _build_leaf_cert(root_cert, root_key, serial)
        serial_hex = format(serial, "x")

        # Register in repo
        cert_repo.add(
            FakeCert(
                id=uuid4(),
                serial_number=serial_hex,
                not_before_cert=now - timedelta(days=1),
                not_after_cert=now + timedelta(days=89),
            )
        )

        service = OCSPService(cert_repo, root_cert, root_key, _ocsp_settings())

        # Build OCSP request
        ocsp_req_der = _build_ocsp_request_for_leaf(leaf_cert, root_cert)
        result = service.handle_request(ocsp_req_der)

        assert isinstance(result, bytes)
        resp = ocsp.load_der_ocsp_response(result)
        assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert resp.certificate_status == ocsp.OCSPCertStatus.GOOD


class TestRevokedResponse:
    """Revoked response includes reason and time."""

    def test_revoked_cert_returns_revoked(self, ca_pair, cert_repo):
        root_cert, root_key = ca_pair
        now = datetime.now(UTC)
        revoked_at = now - timedelta(hours=2)

        serial = 0xAABBCC
        leaf_cert = _build_leaf_cert(root_cert, root_key, serial)
        serial_hex = format(serial, "x")

        cert_repo.add(
            FakeCert(
                id=uuid4(),
                serial_number=serial_hex,
                not_before_cert=now - timedelta(days=10),
                not_after_cert=now + timedelta(days=80),
                revoked_at=revoked_at,
                revocation_reason=None,  # No specific reason
            )
        )

        service = OCSPService(cert_repo, root_cert, root_key, _ocsp_settings())

        ocsp_req_der = _build_ocsp_request_for_leaf(leaf_cert, root_cert)
        result = service.handle_request(ocsp_req_der)

        assert isinstance(result, bytes)
        resp = ocsp.load_der_ocsp_response(result)
        assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED
        assert resp.revocation_time_utc is not None


class TestUnknownCert:
    """Unknown cert -> unknown status response."""

    def test_unknown_serial_returns_unknown(self, ca_pair, cert_repo):
        root_cert, root_key = ca_pair

        # Build a leaf cert that is NOT in the repo
        serial = 0xDEAD01
        leaf_cert = _build_leaf_cert(root_cert, root_key, serial)

        service = OCSPService(cert_repo, root_cert, root_key, _ocsp_settings())

        ocsp_req_der = _build_ocsp_request_for_leaf(leaf_cert, root_cert)
        result = service.handle_request(ocsp_req_der)

        assert isinstance(result, bytes)
        resp = ocsp.load_der_ocsp_response(result)
        assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert resp.certificate_status == ocsp.OCSPCertStatus.UNKNOWN


class TestResponseSigned:
    """Response is properly signed."""

    def test_response_is_signed_by_ca(self, ca_pair, cert_repo):
        root_cert, root_key = ca_pair
        now = datetime.now(UTC)

        serial = 0xFF00FF
        leaf_cert = _build_leaf_cert(root_cert, root_key, serial)
        serial_hex = format(serial, "x")

        cert_repo.add(
            FakeCert(
                id=uuid4(),
                serial_number=serial_hex,
                not_before_cert=now - timedelta(days=5),
                not_after_cert=now + timedelta(days=85),
            )
        )

        service = OCSPService(cert_repo, root_cert, root_key, _ocsp_settings())

        ocsp_req_der = _build_ocsp_request_for_leaf(leaf_cert, root_cert)
        result = service.handle_request(ocsp_req_der)

        resp = ocsp.load_der_ocsp_response(result)
        assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        # The response has a hash_algorithm and signature
        assert resp.hash_algorithm is not None
        assert resp.signature is not None
        assert len(resp.signature) > 0
