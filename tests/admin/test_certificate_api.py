"""Tests for certificate search admin API routes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from flask import Flask

from acmeeh.admin.auth import create_token
from acmeeh.admin.models import AdminUser
from acmeeh.admin.routes import admin_bp
from acmeeh.app.errors import AcmeProblem, register_error_handlers
from acmeeh.config.settings import AdminApiSettings
from acmeeh.core.types import AdminRole, RevocationReason

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

_TOKEN_SECRET = "test-certificate-secret"


def _make_settings() -> AdminApiSettings:
    return AdminApiSettings(
        enabled=True,
        base_path="/api",
        token_secret=_TOKEN_SECRET,
        token_expiry_seconds=3600,
        initial_admin_email="admin@example.com",
        password_length=20,
        default_page_size=50,
        max_page_size=1000,
    )


# ---------------------------------------------------------------------------
# Fake certificate entity
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FakeCertificate:
    id: UUID
    account_id: UUID
    order_id: UUID
    serial_number: str
    fingerprint: str
    not_before_cert: datetime
    not_after_cert: datetime
    san_values: list | None = None
    revoked_at: datetime | None = None
    revocation_reason: RevocationReason | None = None
    created_at: datetime = datetime(1970, 1, 1)


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


class StubAdminService:
    """Stub admin service for certificate route tests."""

    def __init__(self):
        self.users: dict[UUID, AdminUser] = {}
        self._certs: dict[str, FakeCertificate] = {}

    def add_user(self, **kwargs) -> AdminUser:
        defaults = dict(
            id=uuid4(),
            username="admin",
            email="admin@example.com",
            password_hash="hashed",
            role=AdminRole.ADMIN,
            enabled=True,
        )
        defaults.update(kwargs)
        user = AdminUser(**defaults)
        self.users[user.id] = user
        return user

    def add_certificate(self, **kwargs) -> FakeCertificate:
        now = datetime.now(UTC)
        defaults = dict(
            id=uuid4(),
            account_id=uuid4(),
            order_id=uuid4(),
            serial_number="abc123",
            fingerprint="abcdef1234567890",
            not_before_cert=now - timedelta(days=10),
            not_after_cert=now + timedelta(days=80),
            san_values=["example.com"],
        )
        defaults.update(kwargs)
        cert = FakeCertificate(**defaults)
        self._certs[cert.serial_number] = cert
        return cert

    def search_certificates(self, filters, limit=50, offset=0):
        results = list(self._certs.values())
        # Simple filter implementation for tests
        if "serial" in filters:
            results = [c for c in results if c.serial_number == filters["serial"]]
        if "domain" in filters:
            results = [c for c in results if c.san_values and filters["domain"] in c.san_values]
        if "status" in filters:
            if filters["status"] == "revoked":
                results = [c for c in results if c.revoked_at is not None]
            elif filters["status"] == "valid":
                results = [c for c in results if c.revoked_at is None]
        return results[offset : offset + limit]

    def get_certificate_by_serial(self, serial):
        cert = self._certs.get(serial)
        if cert is None:
            raise AcmeProblem("about:blank", "Certificate not found", status=404)
        return cert

    def _log_action(self, user_id, action, *, target_user_id=None, details=None, ip_address=None):
        pass


class StubUserRepo:
    def __init__(self, service):
        self._service = service

    def find_by_id(self, user_id):
        return self._service.users.get(user_id)


class StubContainer:
    def __init__(self, admin_service, settings):
        self.admin_service = admin_service
        self.settings = settings
        self.admin_user_repo = StubUserRepo(admin_service)


class _FakeSettings:
    def __init__(self, admin_api):
        self.admin_api = admin_api


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def admin_service():
    return StubAdminService()


@pytest.fixture()
def app(admin_service):
    flask_app = Flask("test")
    flask_app.config["TESTING"] = True
    admin_settings = _make_settings()
    full_settings = _FakeSettings(admin_settings)
    container = StubContainer(admin_service, full_settings)
    flask_app.extensions["container"] = container
    register_error_handlers(flask_app)
    flask_app.register_blueprint(admin_bp, url_prefix="/api")
    return flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


def _auth_header(user: AdminUser) -> dict:
    token = create_token(user, _TOKEN_SECRET, 3600)
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSearchCertificates:
    """Search certificates with various filters."""

    def test_list_all_certificates(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        admin_service.add_certificate(serial_number="aaa")
        admin_service.add_certificate(serial_number="bbb")

        resp = client.get("/api/certificates", headers=_auth_header(admin))
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert len(data) == 2

    def test_filter_by_domain(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        admin_service.add_certificate(serial_number="c1", san_values=["example.com"])
        admin_service.add_certificate(serial_number="c2", san_values=["other.com"])

        resp = client.get(
            "/api/certificates?domain=example.com",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]["serial_number"] == "c1"

    def test_filter_by_serial(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        admin_service.add_certificate(serial_number="target-serial")
        admin_service.add_certificate(serial_number="other-serial")

        resp = client.get(
            "/api/certificates?serial=target-serial",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]["serial_number"] == "target-serial"

    def test_auditor_can_search(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        admin_service.add_certificate(serial_number="x")

        resp = client.get("/api/certificates", headers=_auth_header(auditor))
        assert resp.status_code == 200

    def test_no_auth_returns_401(self, client):
        resp = client.get("/api/certificates")
        assert resp.status_code == 401


class TestGetCertificateBySerial:
    """Get certificate by serial."""

    def test_get_existing_certificate(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        admin_service.add_certificate(serial_number="found-serial")

        resp = client.get(
            "/api/certificates/found-serial",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["serial_number"] == "found-serial"

    def test_certificate_has_expected_fields(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        admin_service.add_certificate(serial_number="detail-serial")

        resp = client.get(
            "/api/certificates/detail-serial",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "id" in data
        assert "account_id" in data
        assert "serial_number" in data
        assert "fingerprint" in data
        assert "not_before" in data
        assert "not_after" in data
        assert "san_values" in data


class TestCertificateNotFound:
    """Certificate not found -> 404."""

    def test_unknown_serial_returns_404(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        resp = client.get(
            "/api/certificates/nonexistent-serial",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 404
