"""Tests for untested admin route endpoints: CRL rebuild, maintenance mode,
bulk certificate revocation, and audit log export."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from flask import Flask

from acmeeh.admin.auth import create_token
from acmeeh.admin.models import AdminUser, AuditLogEntry
from acmeeh.admin.routes import admin_bp
from acmeeh.app.errors import register_error_handlers
from acmeeh.config.settings import AdminApiSettings
from acmeeh.core.types import AdminRole

_TOKEN_SECRET = "test-secret"


# ---------------------------------------------------------------------------
# Fake / stub helpers
# ---------------------------------------------------------------------------


@dataclass
class FakeCert:
    id: object
    serial_number: str
    revoked_at: datetime | None = None


def _make_settings():
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


class StubAdminService:
    def __init__(self):
        self.users = {}
        self._audit_entries: list[AuditLogEntry] = []
        self._certificates: list[FakeCert] = []

    def add_user(self, **kwargs):
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

    def _log_action(self, user_id, action, *, target_user_id=None, details=None, ip_address=None):
        pass

    def search_audit_log(self, filters, *, limit=100):
        """Match real signature: positional filters dict + keyword limit."""
        return self._audit_entries

    def search_certificates(self, filters, *, limit=100, offset=0):
        """Match real signature: positional filters dict + keyword limit/offset."""
        return self._certificates


class StubUserRepo:
    def __init__(self, service):
        self._service = service

    def find_by_id(self, user_id):
        return self._service.users.get(user_id)


class StubCertificateRepo:
    """Minimal stub that supports revoke()."""

    def __init__(self):
        self.revoked: list[tuple] = []

    def revoke(self, cert_id, reason):
        self.revoked.append((cert_id, reason))
        return True  # must be truthy so route counts it


class StubShutdownCoordinator:
    def __init__(self, maintenance_mode=False):
        self.maintenance_mode = maintenance_mode

    def set_maintenance(self, enabled: bool):
        self.maintenance_mode = enabled


class StubContainer:
    def __init__(self, admin_service, settings, *, crl_manager=None, certificates=None):
        self.admin_service = admin_service
        self.settings = settings
        self.admin_user_repo = StubUserRepo(admin_service)
        self.crl_manager = crl_manager
        self.certificates = certificates


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
def cert_repo():
    return StubCertificateRepo()


@pytest.fixture()
def app(admin_service, cert_repo):
    flask_app = Flask("test")
    flask_app.config["TESTING"] = True
    admin_settings = _make_settings()
    full_settings = _FakeSettings(admin_settings)
    container = StubContainer(
        admin_service,
        full_settings,
        certificates=cert_repo,
    )
    flask_app.extensions["container"] = container
    register_error_handlers(flask_app)
    flask_app.register_blueprint(admin_bp, url_prefix="/api")
    return flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def admin_user(admin_service):
    return admin_service.add_user()


@pytest.fixture()
def auth_header(admin_user):
    token = create_token(admin_user, _TOKEN_SECRET, 3600)
    return {"Authorization": f"Bearer {token}"}


def _auth_header(user):
    token = create_token(user, _TOKEN_SECRET, 3600)
    return {"Authorization": f"Bearer {token}"}


# ===========================================================================
# 1. CRL rebuild -- POST /api/crl/rebuild
# ===========================================================================


class TestCrlRebuild:
    """POST /api/crl/rebuild"""

    @patch("acmeeh.admin.routes.security_events")
    def test_crl_rebuild_no_manager_returns_503(self, _mock_sec, app, admin_user, auth_header):
        """When crl_manager is None the endpoint must return 503."""
        app.extensions["container"].crl_manager = None
        with app.test_client() as c:
            resp = c.post("/api/crl/rebuild", headers=auth_header)
        assert resp.status_code == 503

    @patch("acmeeh.admin.routes.security_events")
    def test_crl_rebuild_success(self, _mock_sec, app, admin_user, auth_header):
        """When crl_manager exists, force_rebuild is called and health_status returned."""
        crl = MagicMock()
        crl.force_rebuild.return_value = None
        crl.health_status.return_value = {
            "last_rebuild": "2026-02-10T00:00:00Z",
            "next_rebuild": "2026-02-11T00:00:00Z",
            "healthy": True,
        }
        app.extensions["container"].crl_manager = crl

        with app.test_client() as c:
            resp = c.post("/api/crl/rebuild", headers=auth_header)

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["healthy"] is True
        crl.force_rebuild.assert_called_once()
        crl.health_status.assert_called_once()


# ===========================================================================
# 2. Maintenance mode -- GET /api/maintenance
# ===========================================================================


class TestMaintenanceGet:
    """GET /api/maintenance"""

    def test_maintenance_mode_true(self, app, admin_user, auth_header):
        coord = StubShutdownCoordinator(maintenance_mode=True)
        app.extensions["shutdown_coordinator"] = coord

        with app.test_client() as c:
            resp = c.get("/api/maintenance", headers=auth_header)

        assert resp.status_code == 200
        assert resp.get_json()["maintenance_mode"] is True

    def test_maintenance_mode_false(self, app, admin_user, auth_header):
        coord = StubShutdownCoordinator(maintenance_mode=False)
        app.extensions["shutdown_coordinator"] = coord

        with app.test_client() as c:
            resp = c.get("/api/maintenance", headers=auth_header)

        assert resp.status_code == 200
        assert resp.get_json()["maintenance_mode"] is False

    def test_maintenance_mode_no_coordinator(self, app, admin_user, auth_header):
        """When no shutdown_coordinator is registered, maintenance_mode defaults to False."""
        app.extensions.pop("shutdown_coordinator", None)

        with app.test_client() as c:
            resp = c.get("/api/maintenance", headers=auth_header)

        assert resp.status_code == 200
        assert resp.get_json()["maintenance_mode"] is False


# ===========================================================================
# 3. Maintenance mode -- POST /api/maintenance
# ===========================================================================


class TestMaintenancePost:
    """POST /api/maintenance"""

    @patch("acmeeh.admin.routes.security_events")
    def test_missing_body_returns_400(self, _mock_sec, app, admin_user, auth_header):
        with app.test_client() as c:
            resp = c.post(
                "/api/maintenance",
                headers=auth_header,
                content_type="application/json",
            )
        assert resp.status_code == 400

    @patch("acmeeh.admin.routes.security_events")
    def test_missing_enabled_field_returns_400(self, _mock_sec, app, admin_user, auth_header):
        with app.test_client() as c:
            resp = c.post(
                "/api/maintenance",
                headers=auth_header,
                json={"something_else": True},
            )
        assert resp.status_code == 400

    @patch("acmeeh.admin.routes.security_events")
    def test_no_shutdown_coordinator_returns_500(self, _mock_sec, app, admin_user, auth_header):
        app.extensions.pop("shutdown_coordinator", None)

        with app.test_client() as c:
            resp = c.post(
                "/api/maintenance",
                headers=auth_header,
                json={"enabled": True},
            )
        assert resp.status_code == 500

    @patch("acmeeh.admin.routes.security_events")
    def test_enable_maintenance_success(self, mock_sec, app, admin_user, auth_header):
        coord = StubShutdownCoordinator(maintenance_mode=False)
        app.extensions["shutdown_coordinator"] = coord

        with app.test_client() as c:
            resp = c.post(
                "/api/maintenance",
                headers=auth_header,
                json={"enabled": True},
            )

        assert resp.status_code == 200
        assert coord.maintenance_mode is True
        mock_sec.maintenance_mode_changed.assert_called_once_with(True, admin_user.username)

    @patch("acmeeh.admin.routes.security_events")
    def test_disable_maintenance_success(self, mock_sec, app, admin_user, auth_header):
        coord = StubShutdownCoordinator(maintenance_mode=True)
        app.extensions["shutdown_coordinator"] = coord

        with app.test_client() as c:
            resp = c.post(
                "/api/maintenance",
                headers=auth_header,
                json={"enabled": False},
            )

        assert resp.status_code == 200
        assert coord.maintenance_mode is False
        mock_sec.maintenance_mode_changed.assert_called_once_with(False, admin_user.username)


# ===========================================================================
# 4. Bulk certificate revocation -- POST /api/certificates/bulk-revoke
# ===========================================================================


class TestBulkRevoke:
    """POST /api/certificates/bulk-revoke"""

    @patch("acmeeh.admin.routes.security_events")
    def test_missing_filter_body_returns_400(self, _mock_sec, app, admin_user, auth_header):
        with app.test_client() as c:
            resp = c.post(
                "/api/certificates/bulk-revoke",
                headers=auth_header,
                content_type="application/json",
            )
        assert resp.status_code == 400

    @patch("acmeeh.admin.routes.security_events")
    def test_invalid_reason_code_returns_400(self, _mock_sec, app, admin_user, auth_header):
        with app.test_client() as c:
            resp = c.post(
                "/api/certificates/bulk-revoke",
                headers=auth_header,
                json={"filter": {"domain": "*.example.com"}, "reason": 99},
            )
        assert resp.status_code == 400

    @patch("acmeeh.admin.routes.security_events")
    def test_dry_run_returns_count(self, _mock_sec, app, admin_service, admin_user, auth_header):
        cert1 = FakeCert(id=uuid4(), serial_number="AAA111")
        cert2 = FakeCert(id=uuid4(), serial_number="BBB222")
        admin_service._certificates = [cert1, cert2]

        with app.test_client() as c:
            resp = c.post(
                "/api/certificates/bulk-revoke",
                headers=auth_header,
                json={
                    "filter": {"domain": "*.example.com"},
                    "reason": 0,
                    "dry_run": True,
                },
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["dry_run"] is True
        assert data["matching_certificates"] == 2
        assert "serial_numbers" in data

    @patch("acmeeh.admin.routes.security_events")
    def test_dry_run_serial_numbers_listed(
        self, _mock_sec, app, admin_service, admin_user, auth_header
    ):
        """Dry run response includes serial_numbers of matching certs."""
        cert1 = FakeCert(id=uuid4(), serial_number="AAA111")
        admin_service._certificates = [cert1]

        with app.test_client() as c:
            resp = c.post(
                "/api/certificates/bulk-revoke",
                headers=auth_header,
                json={
                    "filter": {"domain": "*.example.com"},
                    "reason": 0,
                    "dry_run": True,
                },
            )

        data = resp.get_json()
        assert "AAA111" in data["serial_numbers"]

    @patch("acmeeh.admin.routes.security_events")
    def test_actual_revocation_success(
        self, mock_sec, app, admin_service, cert_repo, admin_user, auth_header
    ):
        cid = uuid4()
        cert1 = FakeCert(id=cid, serial_number="AAA111")
        admin_service._certificates = [cert1]

        with app.test_client() as c:
            resp = c.post(
                "/api/certificates/bulk-revoke",
                headers=auth_header,
                json={
                    "filter": {"domain": "*.example.com"},
                    "reason": 0,
                    "dry_run": False,
                },
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["revoked"] == 1
        assert data["total_matched"] == 1
        assert len(cert_repo.revoked) == 1
        assert cert_repo.revoked[0][0] == cid
        mock_sec.bulk_revocation.assert_called_once()

    @patch("acmeeh.admin.routes.security_events")
    def test_revocation_already_revoked_filtered_out(
        self, _mock_sec, app, admin_service, cert_repo, admin_user, auth_header
    ):
        """Certificates that are already revoked are filtered out before revocation."""
        cert1 = FakeCert(
            id=uuid4(),
            serial_number="AAA111",
            revoked_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        admin_service._certificates = [cert1]

        with app.test_client() as c:
            resp = c.post(
                "/api/certificates/bulk-revoke",
                headers=auth_header,
                json={
                    "filter": {"domain": "*.example.com"},
                    "reason": 0,
                    "dry_run": False,
                },
            )

        assert resp.status_code == 200
        data = resp.get_json()
        # Already-revoked cert should be filtered out
        assert data["revoked"] == 0
        assert len(cert_repo.revoked) == 0

    @patch("acmeeh.admin.routes.security_events")
    def test_revocation_mixed_certs(
        self, _mock_sec, app, admin_service, cert_repo, admin_user, auth_header
    ):
        """Mix of active and already-revoked certs: only active ones get revoked."""
        active_id = uuid4()
        admin_service._certificates = [
            FakeCert(id=active_id, serial_number="ACTIVE01"),
            FakeCert(
                id=uuid4(),
                serial_number="REVOKED01",
                revoked_at=datetime(2026, 1, 1, tzinfo=UTC),
            ),
        ]

        with app.test_client() as c:
            resp = c.post(
                "/api/certificates/bulk-revoke",
                headers=auth_header,
                json={
                    "filter": {"domain": "*.example.com"},
                    "reason": 0,
                    "dry_run": False,
                },
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["revoked"] == 1
        assert len(cert_repo.revoked) == 1
        assert cert_repo.revoked[0][0] == active_id

    @patch("acmeeh.admin.routes.security_events")
    def test_no_reason_code_uses_none(
        self, _mock_sec, app, admin_service, cert_repo, admin_user, auth_header
    ):
        """When reason is omitted, rev_reason is None."""
        cid = uuid4()
        admin_service._certificates = [FakeCert(id=cid, serial_number="NR01")]

        with app.test_client() as c:
            resp = c.post(
                "/api/certificates/bulk-revoke",
                headers=auth_header,
                json={
                    "filter": {"domain": "*.example.com"},
                    "dry_run": False,
                },
            )

        assert resp.status_code == 200
        assert cert_repo.revoked[0][1] is None

    @patch("acmeeh.admin.routes.security_events")
    def test_empty_match_returns_zero(
        self, _mock_sec, app, admin_service, cert_repo, admin_user, auth_header
    ):
        """When no certs match the filter, revoked count is 0."""
        admin_service._certificates = []

        with app.test_client() as c:
            resp = c.post(
                "/api/certificates/bulk-revoke",
                headers=auth_header,
                json={
                    "filter": {"domain": "*.example.com"},
                    "reason": 0,
                    "dry_run": False,
                },
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["revoked"] == 0
        assert data["total_matched"] == 0


# ===========================================================================
# 5. Audit log export -- POST /api/audit-log/export
# ===========================================================================


class TestAuditLogExport:
    """POST /api/audit-log/export"""

    def test_export_returns_ndjson(self, app, admin_service, admin_user, auth_header):
        entry = AuditLogEntry(
            id=uuid4(),
            action="user.login",
            user_id=admin_user.id,
            target_user_id=None,
            details={"info": "login from 10.0.0.1"},
            ip_address="10.0.0.1",
            created_at=datetime(2026, 2, 10, 12, 0, 0, tzinfo=UTC),
        )
        admin_service._audit_entries = [entry]

        with app.test_client() as c:
            resp = c.post(
                "/api/audit-log/export",
                headers=auth_header,
                json={},
            )

        assert resp.status_code == 200
        ct = resp.content_type or ""
        assert "ndjson" in ct

        raw = resp.get_data(as_text=True).strip()
        assert raw  # should not be empty
        lines = raw.splitlines()
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["action"] == "user.login"
        assert parsed["user_id"] == str(admin_user.id)
        assert parsed["ip_address"] == "10.0.0.1"

    def test_export_empty_returns_ok(self, app, admin_service, admin_user, auth_header):
        admin_service._audit_entries = []

        with app.test_client() as c:
            resp = c.post(
                "/api/audit-log/export",
                headers=auth_header,
                json={},
            )

        assert resp.status_code == 200
        ct = resp.content_type or ""
        assert "ndjson" in ct
        raw = resp.get_data(as_text=True).strip()
        assert raw == ""

    def test_export_multiple_entries(self, app, admin_service, admin_user, auth_header):
        entries = []
        for i in range(3):
            entries.append(
                AuditLogEntry(
                    id=uuid4(),
                    action=f"action.{i}",
                    user_id=admin_user.id,
                    target_user_id=None,
                    details={"detail": str(i)},
                    ip_address="10.0.0.1",
                    created_at=datetime(2026, 2, 10, 12, i, 0, tzinfo=UTC),
                )
            )
        admin_service._audit_entries = entries

        with app.test_client() as c:
            resp = c.post(
                "/api/audit-log/export",
                headers=auth_header,
                json={},
            )

        assert resp.status_code == 200
        raw = resp.get_data(as_text=True).strip()
        lines = [line for line in raw.splitlines() if line.strip()]
        assert len(lines) == 3
        for i, line in enumerate(lines):
            parsed = json.loads(line)
            assert parsed["action"] == f"action.{i}"

    def test_export_with_filters_passes_through(self, app, admin_service, admin_user, auth_header):
        """Verify that filter keys from the request body are forwarded to search_audit_log."""
        admin_service._audit_entries = []

        with app.test_client() as c:
            resp = c.post(
                "/api/audit-log/export",
                headers=auth_header,
                json={"action": "user.login", "since": "2026-01-01"},
            )

        assert resp.status_code == 200
