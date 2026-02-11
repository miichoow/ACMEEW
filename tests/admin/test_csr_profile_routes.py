"""Tests for CSR profile admin API routes."""

from __future__ import annotations

from dataclasses import replace
from uuid import UUID, uuid4

import pytest
from flask import Flask

from acmeeh.admin.auth import create_token
from acmeeh.admin.models import AdminUser, AuditLogEntry, CsrProfile
from acmeeh.admin.routes import admin_bp
from acmeeh.app.errors import AcmeProblem, register_error_handlers
from acmeeh.config.settings import AdminApiSettings
from acmeeh.core.types import AdminRole

# ---------------------------------------------------------------------------
# Stub service (extends the pattern from test_routes.py)
# ---------------------------------------------------------------------------

SAMPLE_PROFILE_DATA = {
    "authorized_keys": {"RSA": 2048},
    "wildcard_in_san": False,
}


class StubAdminUserService:
    """Minimal stub to drive route tests without DB."""

    def __init__(self):
        self.users: dict[UUID, AdminUser] = {}
        self.audit_entries: list[AuditLogEntry] = []
        self._profiles: dict[UUID, CsrProfile] = {}
        self._assignments: dict[UUID, UUID] = {}  # account_id → profile_id

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

    # Methods required by other routes (minimal stubs)
    def authenticate(self, username, password, ip_address=None):
        for u in self.users.values():
            if u.username == username:
                return u, "stub-token"
        raise AcmeProblem("urn:acmeeh:admin:error:unauthorized", "Bad creds", 401)

    def list_users(self):
        return list(self.users.values())

    def get_audit_log(self, limit=100):
        return self.audit_entries

    # -- CSR profile stubs --

    def create_csr_profile(
        self, name, profile_data, *, description="", actor_id=None, ip_address=None
    ):
        if not name or not name.strip():
            raise AcmeProblem("about:blank", "'name' required", 400)
        for p in self._profiles.values():
            if p.name == name:
                raise AcmeProblem("urn:acmeeh:admin:error:conflict", "Duplicate", 409)
        profile = CsrProfile(
            id=uuid4(),
            name=name,
            profile_data=profile_data,
            description=description,
            created_by=actor_id,
        )
        self._profiles[profile.id] = profile
        return profile

    def list_csr_profiles(self):
        return list(self._profiles.values())

    def get_csr_profile(self, profile_id) -> tuple[CsrProfile, list[UUID]]:
        profile = self._profiles.get(profile_id)
        if profile is None:
            raise AcmeProblem("about:blank", "Not found", 404)
        acct_ids = [a for a, p in self._assignments.items() if p == profile_id]
        return profile, acct_ids

    def update_csr_profile(
        self, profile_id, name, profile_data, *, description="", actor_id=None, ip_address=None
    ):
        profile = self._profiles.get(profile_id)
        if profile is None:
            raise AcmeProblem("about:blank", "Not found", 404)
        updated = replace(profile, name=name, profile_data=profile_data, description=description)
        self._profiles[profile_id] = updated
        return updated

    def delete_csr_profile(self, profile_id, *, actor_id=None, ip_address=None):
        if profile_id not in self._profiles:
            raise AcmeProblem("about:blank", "Not found", 404)
        del self._profiles[profile_id]

    def assign_profile_to_account(self, profile_id, account_id, *, actor_id=None, ip_address=None):
        if profile_id not in self._profiles:
            raise AcmeProblem("about:blank", "Not found", 404)
        self._assignments[account_id] = profile_id

    def unassign_profile_from_account(
        self, profile_id, account_id, *, actor_id=None, ip_address=None
    ):
        if profile_id not in self._profiles:
            raise AcmeProblem("about:blank", "Not found", 404)
        self._assignments.pop(account_id, None)

    def get_account_csr_profile(self, account_id):
        profile_id = self._assignments.get(account_id)
        if profile_id is None:
            return None
        return self._profiles.get(profile_id)


# ---------------------------------------------------------------------------
# Stub container
# ---------------------------------------------------------------------------


class StubContainer:
    def __init__(self, admin_service, settings):
        self.admin_service = admin_service
        self.settings = settings
        self.admin_user_repo = StubUserRepo(admin_service)


class StubUserRepo:
    def __init__(self, service):
        self._service = service

    def find_by_id(self, user_id):
        return self._service.users.get(user_id)


# ---------------------------------------------------------------------------
# Settings / app fixtures
# ---------------------------------------------------------------------------

_TOKEN_SECRET = "test-route-secret-key-for-csr-profile-tests"


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


class _FakeSettings:
    def __init__(self, admin_api):
        self.admin_api = admin_api


@pytest.fixture()
def admin_service():
    return StubAdminUserService()


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


class TestListCsrProfiles:
    def test_admin_can_list(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.get("/api/csr-profiles", headers=_auth_header(admin))
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)

    def test_auditor_can_list(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        resp = client.get("/api/csr-profiles", headers=_auth_header(auditor))
        assert resp.status_code == 200

    def test_no_auth_returns_401(self, client):
        resp = client.get("/api/csr-profiles")
        assert resp.status_code == 401


class TestCreateCsrProfile:
    def test_admin_can_create(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.post(
            "/api/csr-profiles",
            json={
                "name": "web-servers",
                "profile_data": SAMPLE_PROFILE_DATA,
                "description": "For web servers",
            },
            headers=_auth_header(admin),
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["name"] == "web-servers"
        assert data["description"] == "For web servers"
        assert data["profile_data"] == SAMPLE_PROFILE_DATA

    def test_missing_name(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.post(
            "/api/csr-profiles",
            json={"profile_data": SAMPLE_PROFILE_DATA},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_missing_profile_data(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.post(
            "/api/csr-profiles",
            json={"name": "missing-data"},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400

    def test_auditor_gets_403(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        resp = client.post(
            "/api/csr-profiles",
            json={"name": "x", "profile_data": SAMPLE_PROFILE_DATA},
            headers=_auth_header(auditor),
        )
        assert resp.status_code == 403

    def test_duplicate_name(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        client.post(
            "/api/csr-profiles",
            json={"name": "dup", "profile_data": SAMPLE_PROFILE_DATA},
            headers=_auth_header(admin),
        )
        resp = client.post(
            "/api/csr-profiles",
            json={"name": "dup", "profile_data": SAMPLE_PROFILE_DATA},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 409

    def test_missing_body(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.post(
            "/api/csr-profiles",
            content_type="application/json",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 400


class TestGetCsrProfile:
    def test_get_existing(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        create_resp = client.post(
            "/api/csr-profiles",
            json={"name": "get-test", "profile_data": SAMPLE_PROFILE_DATA},
            headers=_auth_header(admin),
        )
        profile_id = create_resp.get_json()["id"]
        resp = client.get(f"/api/csr-profiles/{profile_id}", headers=_auth_header(admin))
        assert resp.status_code == 200
        assert resp.get_json()["name"] == "get-test"
        assert "account_ids" in resp.get_json()

    def test_not_found(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.get(f"/api/csr-profiles/{uuid4()}", headers=_auth_header(admin))
        assert resp.status_code == 404


class TestUpdateCsrProfile:
    def test_admin_can_update(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        create_resp = client.post(
            "/api/csr-profiles",
            json={"name": "old", "profile_data": SAMPLE_PROFILE_DATA},
            headers=_auth_header(admin),
        )
        profile_id = create_resp.get_json()["id"]
        resp = client.put(
            f"/api/csr-profiles/{profile_id}",
            json={
                "name": "new",
                "profile_data": {"authorized_keys": {"RSA": 4096}},
                "description": "Updated",
            },
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200
        assert resp.get_json()["name"] == "new"

    def test_not_found(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.put(
            f"/api/csr-profiles/{uuid4()}",
            json={"name": "x", "profile_data": SAMPLE_PROFILE_DATA},
            headers=_auth_header(admin),
        )
        assert resp.status_code == 404

    def test_auditor_gets_403(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        resp = client.put(
            f"/api/csr-profiles/{uuid4()}",
            json={"name": "x", "profile_data": SAMPLE_PROFILE_DATA},
            headers=_auth_header(auditor),
        )
        assert resp.status_code == 403


class TestDeleteCsrProfile:
    def test_admin_can_delete(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        create_resp = client.post(
            "/api/csr-profiles",
            json={"name": "del-test", "profile_data": SAMPLE_PROFILE_DATA},
            headers=_auth_header(admin),
        )
        profile_id = create_resp.get_json()["id"]
        resp = client.delete(f"/api/csr-profiles/{profile_id}", headers=_auth_header(admin))
        assert resp.status_code == 204

    def test_not_found(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.delete(f"/api/csr-profiles/{uuid4()}", headers=_auth_header(admin))
        assert resp.status_code == 404

    def test_auditor_gets_403(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        resp = client.delete(f"/api/csr-profiles/{uuid4()}", headers=_auth_header(auditor))
        assert resp.status_code == 403


class TestAssignProfile:
    def test_admin_can_assign(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        create_resp = client.post(
            "/api/csr-profiles",
            json={"name": "assign-test", "profile_data": SAMPLE_PROFILE_DATA},
            headers=_auth_header(admin),
        )
        profile_id = create_resp.get_json()["id"]
        acct_id = uuid4()
        resp = client.put(
            f"/api/csr-profiles/{profile_id}/accounts/{acct_id}",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 204

    def test_nonexistent_profile(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.put(
            f"/api/csr-profiles/{uuid4()}/accounts/{uuid4()}",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 404

    def test_auditor_gets_403(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        resp = client.put(
            f"/api/csr-profiles/{uuid4()}/accounts/{uuid4()}",
            headers=_auth_header(auditor),
        )
        assert resp.status_code == 403


class TestUnassignProfile:
    def test_admin_can_unassign(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        create_resp = client.post(
            "/api/csr-profiles",
            json={"name": "unassign-test", "profile_data": SAMPLE_PROFILE_DATA},
            headers=_auth_header(admin),
        )
        profile_id = create_resp.get_json()["id"]
        acct_id = uuid4()
        client.put(
            f"/api/csr-profiles/{profile_id}/accounts/{acct_id}",
            headers=_auth_header(admin),
        )
        resp = client.delete(
            f"/api/csr-profiles/{profile_id}/accounts/{acct_id}",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 204

    def test_nonexistent_profile(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.delete(
            f"/api/csr-profiles/{uuid4()}/accounts/{uuid4()}",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 404


class TestGetAccountCsrProfile:
    def test_no_profile(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        resp = client.get(
            f"/api/accounts/{uuid4()}/csr-profile",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200
        assert resp.get_json() is None

    def test_has_profile(self, client, admin_service):
        admin = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        create_resp = client.post(
            "/api/csr-profiles",
            json={"name": "acct-profile", "profile_data": SAMPLE_PROFILE_DATA},
            headers=_auth_header(admin),
        )
        profile_id = create_resp.get_json()["id"]
        acct_id = uuid4()
        client.put(
            f"/api/csr-profiles/{profile_id}/accounts/{acct_id}",
            headers=_auth_header(admin),
        )
        resp = client.get(
            f"/api/accounts/{acct_id}/csr-profile",
            headers=_auth_header(admin),
        )
        assert resp.status_code == 200
        assert resp.get_json()["name"] == "acct-profile"

    def test_auditor_can_view(self, client, admin_service):
        auditor = admin_service.add_user(username="auditor", role=AdminRole.AUDITOR)
        resp = client.get(
            f"/api/accounts/{uuid4()}/csr-profile",
            headers=_auth_header(auditor),
        )
        assert resp.status_code == 200
