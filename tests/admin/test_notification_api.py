"""Tests for notification management admin API routes."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from flask import Flask

from acmeeh.admin.auth import create_token
from acmeeh.admin.models import AdminUser
from acmeeh.admin.routes import admin_bp
from acmeeh.app.errors import register_error_handlers
from acmeeh.config.settings import AdminApiSettings
from acmeeh.core.types import AdminRole, NotificationStatus, NotificationType
from acmeeh.models.notification import Notification

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

_TOKEN_SECRET = "test-notification-secret"


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
# Stubs
# ---------------------------------------------------------------------------


class StubAdminService:
    """Stub admin service for notification route tests."""

    def __init__(self):
        self.users: dict[UUID, AdminUser] = {}
        self._notifications: list[Notification] = []
        self._purge_count = 0
        self._retry_count = 0

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

    def add_notification(self, **kwargs) -> Notification:
        defaults = dict(
            id=uuid4(),
            notification_type=NotificationType.DELIVERY_SUCCEEDED,
            recipient="user@example.com",
            subject="Test notification",
            body="Body text",
            status=NotificationStatus.SENT,
        )
        defaults.update(kwargs)
        n = Notification(**defaults)
        self._notifications.append(n)
        return n

    def list_notifications(self, status=None, limit=50, offset=0):
        results = self._notifications
        if status:
            results = [n for n in results if n.status.value == status]
        return results[offset : offset + limit]

    def retry_failed_notifications(self):
        self._retry_count += 1
        return 3  # return a fixed count

    def purge_notifications(self, days):
        self._purge_count += 1
        return 5  # return a fixed count

    def _log_action(self, user_id, action, *, target_user_id=None, details=None, ip_address=None):
        pass  # no-op for tests


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


class TestListNotifications:
    """List notifications with status filter."""

    def test_list_all(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        admin_service.add_notification()
        admin_service.add_notification(status=NotificationStatus.FAILED)

        resp = client.get("/api/notifications", headers=_auth_header(admin))
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert len(data) == 2

    def test_filter_by_status(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        admin_service.add_notification(status=NotificationStatus.SENT)
        admin_service.add_notification(status=NotificationStatus.FAILED)

        resp = client.get(
            "/api/notifications?status=failed",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]["status"] == "failed"

    def test_auditor_cannot_list(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        resp = client.get("/api/notifications", headers=_auth_header(auditor))
        assert resp.status_code == 403


class TestRetryNotifications:
    """Retry failed notifications returns count."""

    def test_retry_returns_count(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        resp = client.post("/api/notifications/retry", headers=_auth_header(admin))
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["retried"] == 3


class TestPurgeNotifications:
    """Purge notifications older than N days."""

    def test_purge_returns_count(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        resp = client.post(
            "/api/notifications/purge",
            json={"days": 30},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["purged"] == 5

    def test_purge_with_custom_days(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        resp = client.post(
            "/api/notifications/purge",
            json={"days": 7},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200

    def test_invalid_days_returns_400(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        resp = client.post(
            "/api/notifications/purge",
            json={"days": 0},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_negative_days_returns_400(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        resp = client.post(
            "/api/notifications/purge",
            json={"days": -5},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_non_integer_days_returns_400(self, client, admin_service):
        admin = admin_service.add_user(role=AdminRole.ADMIN)
        resp = client.post(
            "/api/notifications/purge",
            json={"days": "thirty"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400
