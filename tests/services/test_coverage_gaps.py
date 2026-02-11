"""Tests covering uncovered lines in several service modules.

Targets:
1. acmeeh.logging.security_events — 14 uncovered functions
2. acmeeh.services.key_change.KeyChangeService — 4 branches
3. acmeeh.services.nonce.NonceService — expired nonce + gc
4. acmeeh.services.ocsp.OCSPService — revoked w/ reason + sign exception
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

# ===================================================================
# Section 1: security_events — exercise all 14 uncovered functions
# ===================================================================
from acmeeh.logging import security_events


class TestSecurityEventsKeyChanged:
    """security_events.key_changed"""

    def test_key_changed_does_not_raise(self):
        security_events.key_changed(uuid4(), "old-thumb", "new-thumb")

    def test_key_changed_with_specific_ids(self):
        aid = uuid4()
        security_events.key_changed(aid, "abc123", "def456")


class TestSecurityEventsAdminLogin:
    """admin_login_failed / succeeded / lockout"""

    def test_admin_login_failed(self):
        security_events.admin_login_failed("admin", "192.168.1.1")

    def test_admin_login_failed_empty_ip(self):
        security_events.admin_login_failed("root", "")

    def test_admin_login_succeeded(self):
        security_events.admin_login_succeeded("admin", "10.0.0.1")

    def test_admin_login_succeeded_different_user(self):
        security_events.admin_login_succeeded("operator", "172.16.0.1")

    def test_admin_login_lockout(self):
        security_events.admin_login_lockout("admin:192.168.1.1")

    def test_admin_login_lockout_empty_key(self):
        security_events.admin_login_lockout("")


class TestSecurityEventsEab:
    """eab_credential_used"""

    def test_eab_credential_used(self):
        security_events.eab_credential_used(uuid4(), "eab-kid-001")

    def test_eab_credential_used_long_kid(self):
        security_events.eab_credential_used(uuid4(), "a" * 200)


class TestSecurityEventsOrderRejected:
    """order_rejected"""

    def test_order_rejected(self):
        security_events.order_rejected(uuid4(), ["example.com"], "policy")

    def test_order_rejected_multiple_identifiers(self):
        security_events.order_rejected(uuid4(), ["a.com", "b.com", "c.com"], "rate-limit")


class TestSecurityEventsNonceInvalid:
    """nonce_invalid — short and long nonce values"""

    def test_nonce_invalid_short_value(self):
        security_events.nonce_invalid("10.0.0.1", "abc", "expired")

    def test_nonce_invalid_exact_16(self):
        security_events.nonce_invalid("10.0.0.1", "a" * 16, "expired")

    def test_nonce_invalid_long_value_truncated(self):
        # Longer than _NONCE_PREVIEW_LENGTH (16) → triggers truncation
        security_events.nonce_invalid("10.0.0.1", "x" * 100, "replayed")

    def test_nonce_invalid_17_chars(self):
        # Just over the limit
        security_events.nonce_invalid("10.0.0.1", "a" * 17, "unknown")


class TestSecurityEventsJwsAuthFailed:
    """jws_auth_failed"""

    def test_jws_auth_failed_no_thumbprint(self):
        security_events.jws_auth_failed("10.0.0.1", "bad signature")

    def test_jws_auth_failed_with_thumbprint(self):
        security_events.jws_auth_failed("10.0.0.1", "bad signature", thumbprint="abc123")


class TestSecurityEventsKeyPolicyViolation:
    """key_policy_violation"""

    def test_key_policy_violation(self):
        security_events.key_policy_violation("10.0.0.1", "RSA key too short")


class TestSecurityEventsAuthzDeactivated:
    """authorization_deactivated"""

    def test_authorization_deactivated(self):
        security_events.authorization_deactivated(uuid4(), uuid4(), "example.com")


class TestSecurityEventsExternalCa:
    """external_ca_call"""

    def test_external_ca_call_success(self):
        security_events.external_ca_call("sign", "internal", success=True)

    def test_external_ca_call_failure(self):
        security_events.external_ca_call("revoke", "external", success=False, detail="timeout")

    def test_external_ca_call_with_serial(self):
        security_events.external_ca_call("sign", "hsm", serial_number="abcdef", success=True)


class TestSecurityEventsMaintenanceMode:
    """maintenance_mode_changed"""

    def test_maintenance_enabled(self):
        security_events.maintenance_mode_changed(True, "admin")

    def test_maintenance_disabled(self):
        security_events.maintenance_mode_changed(False, "operator")


class TestSecurityEventsBulkRevocation:
    """bulk_revocation"""

    def test_bulk_revocation_basic(self):
        security_events.bulk_revocation("admin", 42)

    def test_bulk_revocation_with_reason_and_filter(self):
        security_events.bulk_revocation(
            "admin", 10, reason="key_compromise", filter_desc="serial=abc*"
        )


# ===================================================================
# Section 2: KeyChangeService — 4 uncovered branches
# ===================================================================


from acmeeh.app.errors import AcmeProblem
from acmeeh.core.jws import compute_thumbprint
from acmeeh.services.key_change import KeyChangeService

_JWK_A = {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
}
_JWK_B = {
    "kty": "EC",
    "crv": "P-256",
    "x": "iGpR3MZjpMZW8lG9bwDMJUjbFYyIyP0t63xYP-kJuZo",
    "y": "fU8HcVgA-zd5WGjjHbWYPJVfCJnVACnRwZxNKIJiEBs",
}

_THUMB_A = compute_thumbprint(_JWK_A)
_THUMB_B = compute_thumbprint(_JWK_B)


def _mock_account(thumbprint: str) -> MagicMock:
    acct = MagicMock()
    acct.jwk_thumbprint = thumbprint
    return acct


class TestKeyChangeNewKeyAlreadyInUse:
    """Line 66 — new key already associated with another account."""

    def test_raises_409_when_new_key_exists(self):
        repo = MagicMock()
        repo.find_by_thumbprint.return_value = _mock_account(_THUMB_B)

        svc = KeyChangeService(repo)
        with pytest.raises(AcmeProblem) as exc_info:
            svc.rollover(uuid4(), _JWK_A, _JWK_B)

        assert exc_info.value.status == 409
        assert "already associated" in str(exc_info.value.detail)


class TestKeyChangeAccountNotFound:
    """Line 76 — account not found."""

    def test_raises_404_when_account_missing(self):
        repo = MagicMock()
        repo.find_by_thumbprint.return_value = None
        repo.find_by_id.return_value = None

        svc = KeyChangeService(repo)
        with pytest.raises(AcmeProblem) as exc_info:
            svc.rollover(uuid4(), _JWK_A, _JWK_B)

        assert exc_info.value.status == 404
        assert "not found" in str(exc_info.value.detail).lower()


class TestKeyChangeOldKeyMismatch:
    """Line 78 — old key does not match the account's current key."""

    def test_raises_malformed_when_old_key_wrong(self):
        different_thumb = "totally-different-thumbprint"
        repo = MagicMock()
        repo.find_by_thumbprint.return_value = None
        repo.find_by_id.return_value = _mock_account(different_thumb)

        svc = KeyChangeService(repo)
        with pytest.raises(AcmeProblem) as exc_info:
            svc.rollover(uuid4(), _JWK_A, _JWK_B)

        assert "does not match" in str(exc_info.value.detail).lower()


class TestKeyChangeUpdateFails:
    """Line 86 — update_jwk returns None."""

    def test_raises_500_when_update_returns_none(self):
        repo = MagicMock()
        repo.find_by_thumbprint.return_value = None
        repo.find_by_id.return_value = _mock_account(_THUMB_A)
        repo.update_jwk.return_value = None

        svc = KeyChangeService(repo)
        with pytest.raises(AcmeProblem) as exc_info:
            svc.rollover(uuid4(), _JWK_A, _JWK_B)

        assert exc_info.value.status == 500
        assert "rollover failed" in str(exc_info.value.detail).lower()


class TestKeyChangeSuccess:
    """Happy-path: key rollover succeeds."""

    def test_returns_updated_account(self):
        updated = _mock_account(_THUMB_B)
        repo = MagicMock()
        repo.find_by_thumbprint.return_value = None
        repo.find_by_id.return_value = _mock_account(_THUMB_A)
        repo.update_jwk.return_value = updated

        svc = KeyChangeService(repo)
        result = svc.rollover(uuid4(), _JWK_A, _JWK_B)
        assert result is updated


# ===================================================================
# Section 3: NonceService — expired nonce (lines 85-90) + gc (line 100)
# ===================================================================


from acmeeh.models.nonce import Nonce
from acmeeh.services.nonce import NonceService


def _nonce_settings(**overrides):
    """Build a minimal NonceSettings-like object."""
    defaults = dict(
        expiry_seconds=3600,
        gc_interval_seconds=300,
        length=32,
        audit_consumed=False,
        max_age_seconds=60,
    )
    defaults.update(overrides)
    ns = MagicMock()
    for k, v in defaults.items():
        setattr(ns, k, v)
    return ns


class TestNonceServiceExpiredNonce:
    """Lines 85-90 — nonce exceeds max_age, consume returns False."""

    def test_stale_nonce_rejected(self):
        old_time = datetime.now(UTC) - timedelta(seconds=120)
        nonce_entity = Nonce(
            nonce="test-nonce-123",
            expires_at=datetime.now(UTC) + timedelta(seconds=3600),
            created_at=old_time,
        )
        repo = MagicMock()
        repo.find_by_id.return_value = nonce_entity
        repo.consume.return_value = True

        settings = _nonce_settings(max_age_seconds=60)
        svc = NonceService(repo, settings)

        result = svc.consume("test-nonce-123")

        assert result is False
        repo.consume.assert_called_once_with("test-nonce-123")

    def test_fresh_nonce_accepted(self):
        recent = datetime.now(UTC) - timedelta(seconds=10)
        nonce_entity = Nonce(
            nonce="fresh-nonce",
            expires_at=datetime.now(UTC) + timedelta(seconds=3600),
            created_at=recent,
        )
        repo = MagicMock()
        repo.find_by_id.return_value = nonce_entity
        repo.consume.return_value = True

        settings = _nonce_settings(max_age_seconds=60)
        svc = NonceService(repo, settings)

        result = svc.consume("fresh-nonce")
        assert result is True

    def test_nonce_not_found_returns_false(self):
        repo = MagicMock()
        repo.find_by_id.return_value = None

        settings = _nonce_settings(max_age_seconds=60)
        svc = NonceService(repo, settings)

        result = svc.consume("missing")
        assert result is False

    def test_nonce_without_created_at(self):
        """Nonce with created_at=None skips max-age check."""
        nonce_entity = Nonce(
            nonce="no-ts",
            expires_at=datetime.now(UTC) + timedelta(seconds=3600),
            created_at=None,
        )
        repo = MagicMock()
        repo.find_by_id.return_value = nonce_entity
        repo.consume.return_value = True

        settings = _nonce_settings(max_age_seconds=60)
        svc = NonceService(repo, settings)

        result = svc.consume("no-ts")
        assert result is True


class TestNonceServiceGc:
    """Line 100 — gc() delegates to repo.gc_expired()."""

    def test_gc_returns_count(self):
        repo = MagicMock()
        repo.gc_expired.return_value = 7

        settings = _nonce_settings(max_age_seconds=60)
        svc = NonceService(repo, settings)

        assert svc.gc() == 7
        repo.gc_expired.assert_called_once()

    def test_gc_returns_zero(self):
        repo = MagicMock()
        repo.gc_expired.return_value = 0

        settings = _nonce_settings(max_age_seconds=60)
        svc = NonceService(repo, settings)

        assert svc.gc() == 0


class TestNonceServiceMaxAgeFallback:
    """Constructor falls back to min(expiry_seconds, 300) when max_age_seconds=0."""

    def test_max_age_defaults_to_min_expiry_or_300(self):
        settings = _nonce_settings(max_age_seconds=0, expiry_seconds=600)
        svc = NonceService(MagicMock(), settings)
        assert svc._max_age == timedelta(seconds=300)

    def test_max_age_uses_expiry_when_less_than_300(self):
        settings = _nonce_settings(max_age_seconds=0, expiry_seconds=120)
        svc = NonceService(MagicMock(), settings)
        assert svc._max_age == timedelta(seconds=120)


# ===================================================================
# Section 4: OCSPService — revoked with reason + sign exception
# ===================================================================


from acmeeh.config.settings import OcspSettings
from acmeeh.core.types import RevocationReason
from acmeeh.services.ocsp import OCSPService


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
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _build_leaf_cert(ca_cert, ca_key, serial: int) -> x509.Certificate:
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


@pytest.fixture
def ca_pair():
    return _generate_ca()


@pytest.fixture
def cert_repo():
    return StubCertRepo()


class TestOCSPRevokedWithReason:
    """Lines 93-96 — revoked cert with a revocation_reason attribute."""

    def test_revoked_with_key_compromise_reason(self, ca_pair, cert_repo):
        root_cert, root_key = ca_pair
        now = datetime.now(UTC)
        revoked_at = now - timedelta(hours=1)

        serial = 0xBEEF01
        leaf_cert = _build_leaf_cert(root_cert, root_key, serial)
        serial_hex = format(serial, "x")

        cert_repo.add(
            FakeCert(
                id=uuid4(),
                serial_number=serial_hex,
                not_before_cert=now - timedelta(days=5),
                not_after_cert=now + timedelta(days=85),
                revoked_at=revoked_at,
                revocation_reason=RevocationReason.KEY_COMPROMISE,
            )
        )

        service = OCSPService(cert_repo, root_cert, root_key, _ocsp_settings())
        ocsp_req_der = _build_ocsp_request_for_leaf(leaf_cert, root_cert)
        result = service.handle_request(ocsp_req_der)

        resp = ocsp.load_der_ocsp_response(result)
        assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED

    def test_revoked_with_cessation_reason(self, ca_pair, cert_repo):
        root_cert, root_key = ca_pair
        now = datetime.now(UTC)

        serial = 0xBEEF02
        leaf_cert = _build_leaf_cert(root_cert, root_key, serial)
        serial_hex = format(serial, "x")

        cert_repo.add(
            FakeCert(
                id=uuid4(),
                serial_number=serial_hex,
                not_before_cert=now - timedelta(days=5),
                not_after_cert=now + timedelta(days=85),
                revoked_at=now - timedelta(hours=2),
                revocation_reason=RevocationReason.CESSATION_OF_OPERATION,
            )
        )

        service = OCSPService(cert_repo, root_cert, root_key, _ocsp_settings())
        ocsp_req_der = _build_ocsp_request_for_leaf(leaf_cert, root_cert)
        result = service.handle_request(ocsp_req_der)

        resp = ocsp.load_der_ocsp_response(result)
        assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED

    def test_revoked_with_unspecified_reason(self, ca_pair, cert_repo):
        root_cert, root_key = ca_pair
        now = datetime.now(UTC)

        serial = 0xBEEF03
        leaf_cert = _build_leaf_cert(root_cert, root_key, serial)
        serial_hex = format(serial, "x")

        cert_repo.add(
            FakeCert(
                id=uuid4(),
                serial_number=serial_hex,
                not_before_cert=now - timedelta(days=5),
                not_after_cert=now + timedelta(days=85),
                revoked_at=now - timedelta(hours=3),
                revocation_reason=RevocationReason.UNSPECIFIED,
            )
        )

        service = OCSPService(cert_repo, root_cert, root_key, _ocsp_settings())
        ocsp_req_der = _build_ocsp_request_for_leaf(leaf_cert, root_cert)
        result = service.handle_request(ocsp_req_der)

        resp = ocsp.load_der_ocsp_response(result)
        assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED


class TestOCSPSignException:
    """Lines 128-130 — exception during builder.sign returns INTERNAL_ERROR."""

    def test_sign_failure_returns_internal_error(self, ca_pair, cert_repo):
        root_cert, root_key = ca_pair
        now = datetime.now(UTC)

        serial = 0xDEAD02
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

        # Patch OCSPResponseBuilder.sign to raise an exception
        with patch.object(ocsp.OCSPResponseBuilder, "sign", side_effect=RuntimeError("boom")):
            result = service.handle_request(ocsp_req_der)

        resp = ocsp.load_der_ocsp_response(result)
        assert resp.response_status == ocsp.OCSPResponseStatus.INTERNAL_ERROR

    def test_sign_failure_with_revoked_cert(self, ca_pair, cert_repo):
        root_cert, root_key = ca_pair
        now = datetime.now(UTC)

        serial = 0xDEAD03
        leaf_cert = _build_leaf_cert(root_cert, root_key, serial)
        serial_hex = format(serial, "x")

        cert_repo.add(
            FakeCert(
                id=uuid4(),
                serial_number=serial_hex,
                not_before_cert=now - timedelta(days=5),
                not_after_cert=now + timedelta(days=85),
                revoked_at=now - timedelta(hours=1),
                revocation_reason=RevocationReason.KEY_COMPROMISE,
            )
        )

        service = OCSPService(cert_repo, root_cert, root_key, _ocsp_settings())

        ocsp_req_der = _build_ocsp_request_for_leaf(leaf_cert, root_cert)

        with patch.object(ocsp.OCSPResponseBuilder, "sign", side_effect=ValueError("bad key")):
            result = service.handle_request(ocsp_req_der)

        resp = ocsp.load_der_ocsp_response(result)
        assert resp.response_status == ocsp.OCSPResponseStatus.INTERNAL_ERROR
