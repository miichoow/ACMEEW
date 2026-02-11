"""Tests for admin token blacklist and logout endpoint."""

from __future__ import annotations

import threading
import time
from uuid import UUID, uuid4

import pytest
from flask import Flask

from acmeeh.admin.auth import (
    TokenBlacklist,
    create_token,
    get_token_blacklist,
)
from acmeeh.admin.models import AdminUser
from acmeeh.admin.routes import admin_bp
from acmeeh.app.errors import AcmeProblem, register_error_handlers
from acmeeh.config.settings import AdminApiSettings
from acmeeh.core.types import AdminRole

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_blacklist():
    """Clear the module-level blacklist before and after each test."""
    bl = get_token_blacklist()
    with bl._lock:
        bl._revoked.clear()
    yield
    with bl._lock:
        bl._revoked.clear()


def _make_user(**kwargs) -> AdminUser:
    defaults = dict(
        id=uuid4(),
        username="testadmin",
        email="admin@example.com",
        password_hash="hashed",
        role=AdminRole.ADMIN,
        enabled=True,
    )
    defaults.update(kwargs)
    return AdminUser(**defaults)


# ---------------------------------------------------------------------------
# Stub service / container (mirrors test_routes.py pattern)
# ---------------------------------------------------------------------------


class StubAdminUserService:
    """Minimal stub to drive route tests without DB."""

    def __init__(self):
        self.users: dict[UUID, AdminUser] = {}

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

    def authenticate(self, username, password, ip_address=None):
        for u in self.users.values():
            if u.username == username:
                return u, "stub-token"
        raise AcmeProblem("urn:acmeeh:admin:error:unauthorized", "Bad creds", 401)

    def list_users(self):
        return list(self.users.values())


class StubUserRepo:
    def __init__(self, service):
        self._service = service

    def find_by_id(self, user_id):
        return self._service.users.get(user_id)


class _FakeSettings:
    def __init__(self, admin_api):
        self.admin_api = admin_api


class StubContainer:
    def __init__(self, admin_service, settings):
        self.admin_service = admin_service
        self.settings = settings
        self.admin_user_repo = StubUserRepo(admin_service)


_TOKEN_SECRET = "test-blacklist-secret-key-for-tests"


def _make_admin_settings() -> AdminApiSettings:
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


@pytest.fixture()
def admin_service():
    return StubAdminUserService()


@pytest.fixture()
def app(admin_service):
    flask_app = Flask("test")
    flask_app.config["TESTING"] = True
    admin_settings = _make_admin_settings()
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


def _bearer_token(user: AdminUser) -> str:
    return create_token(user, _TOKEN_SECRET, 3600)


# ---------------------------------------------------------------------------
# Unit tests — TokenBlacklist
# ---------------------------------------------------------------------------


class TestRevokeAndCheck:
    """test_revoke_and_check: Revoke a token, verify is_revoked returns True."""

    def test_revoke_and_check(self):
        bl = TokenBlacklist()
        token = "payload.timestamp.signature123"
        bl.revoke_token(token)
        assert bl.is_revoked(token) is True


class TestNotRevoked:
    """test_not_revoked: Fresh token not in blacklist."""

    def test_not_revoked(self):
        bl = TokenBlacklist()
        token = "payload.timestamp.signatureABC"
        assert bl.is_revoked(token) is False

    def test_different_token_not_revoked(self):
        bl = TokenBlacklist()
        bl.revoke_token("payload.timestamp.sig1")
        assert bl.is_revoked("payload.timestamp.sig2") is False


class TestCleanupRemovesOldEntries:
    """test_cleanup_removes_old_entries: Add entries, cleanup with max_age, verify old removed."""

    def test_cleanup_removes_old_entries(self):
        bl = TokenBlacklist()
        token = "payload.timestamp.oldsig"

        # Manually insert an entry with a timestamp far in the past
        sig = bl._extract_signature(token)
        with bl._lock:
            bl._revoked[sig] = time.monotonic() - 7200  # 2 hours ago

        removed = bl.cleanup(max_age_seconds=3600)  # keep only entries < 1 hour old

        assert removed == 1
        assert bl.is_revoked(token) is False


class TestCleanupKeepsRecent:
    """test_cleanup_keeps_recent: Recent entries survive cleanup."""

    def test_cleanup_keeps_recent(self):
        bl = TokenBlacklist()
        token = "payload.timestamp.recentsig"
        bl.revoke_token(token)  # added just now

        removed = bl.cleanup(max_age_seconds=3600)

        assert removed == 0
        assert bl.is_revoked(token) is True

    def test_cleanup_mixed_old_and_recent(self):
        bl = TokenBlacklist()
        old_token = "payload.timestamp.old"
        new_token = "payload.timestamp.new"

        # Insert old entry manually
        old_sig = bl._extract_signature(old_token)
        with bl._lock:
            bl._revoked[old_sig] = time.monotonic() - 7200

        # Insert recent entry normally
        bl.revoke_token(new_token)

        removed = bl.cleanup(max_age_seconds=3600)

        assert removed == 1
        assert bl.is_revoked(old_token) is False
        assert bl.is_revoked(new_token) is True


class TestExtractSignature:
    """test_extract_signature: Verify correct signature extraction from itsdangerous-style tokens."""

    def test_extract_signature_three_parts(self):
        # itsdangerous tokens: payload.timestamp.signature
        token = "eyJhbGciOiJIUzI1NiJ9.MTY5NjAwMDAwMA.kX9z3yQfW_abcdef"
        sig = TokenBlacklist._extract_signature(token)
        assert sig == "kX9z3yQfW_abcdef"

    def test_extract_signature_two_parts(self):
        token = "payload_data.signature_part"
        sig = TokenBlacklist._extract_signature(token)
        assert sig == "signature_part"

    def test_extract_signature_no_dot(self):
        # No dot: the whole token is returned as fallback
        token = "single_segment_token"
        sig = TokenBlacklist._extract_signature(token)
        assert sig == "single_segment_token"

    def test_extract_uses_rsplit(self):
        # rsplit(".", 1) means only the last segment after the final dot
        token = "a.b.c.d.e"
        sig = TokenBlacklist._extract_signature(token)
        assert sig == "e"


class TestThreadSafety:
    """test_thread_safety: Multiple threads revoking/checking concurrently."""

    def test_thread_safety(self):
        bl = TokenBlacklist()
        errors = []
        num_threads = 20
        tokens_per_thread = 50

        def revoke_worker(thread_id):
            try:
                for i in range(tokens_per_thread):
                    token = f"payload.ts.thread{thread_id}_tok{i}"
                    bl.revoke_token(token)
            except Exception as exc:
                errors.append(exc)

        def check_worker(thread_id):
            try:
                for i in range(tokens_per_thread):
                    token = f"payload.ts.thread{thread_id}_tok{i}"
                    # Just exercise the method; no assertion on result since
                    # the revoke_worker may not have inserted it yet.
                    bl.is_revoked(token)
            except Exception as exc:
                errors.append(exc)

        threads = []
        for t in range(num_threads):
            threads.append(threading.Thread(target=revoke_worker, args=(t,)))
            threads.append(threading.Thread(target=check_worker, args=(t,)))

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert errors == [], f"Thread errors: {errors}"

        # All revoked tokens should now be found
        for t in range(num_threads):
            for i in range(tokens_per_thread):
                token = f"payload.ts.thread{t}_tok{i}"
                assert bl.is_revoked(token) is True

    def test_concurrent_cleanup(self):
        bl = TokenBlacklist()
        errors = []

        # Pre-populate with old and new entries
        for i in range(100):
            sig = f"old_{i}"
            with bl._lock:
                bl._revoked[sig] = time.monotonic() - 7200
        for i in range(100):
            bl.revoke_token(f"payload.ts.new_{i}")

        def cleanup_worker():
            try:
                bl.cleanup(max_age_seconds=3600)
            except Exception as exc:
                errors.append(exc)

        def revoke_worker():
            try:
                for i in range(50):
                    bl.revoke_token(f"payload.ts.extra_{i}")
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=cleanup_worker),
            threading.Thread(target=cleanup_worker),
            threading.Thread(target=revoke_worker),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert errors == [], f"Thread errors: {errors}"


# ---------------------------------------------------------------------------
# Integration tests — require_admin_auth rejects revoked tokens
# ---------------------------------------------------------------------------


class TestRequireAdminAuthRejectsRevokedToken:
    """test_require_admin_auth_rejects_revoked_token:
    Mock Flask app with admin routes, revoke a token, verify 401 on next request.
    """

    def test_require_admin_auth_rejects_revoked_token(self, client, admin_service):
        user = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        token = _bearer_token(user)
        headers = {"Authorization": f"Bearer {token}"}

        # First request should succeed
        resp = client.get("/api/users", headers=headers)
        assert resp.status_code == 200

        # Revoke the token via the singleton blacklist
        get_token_blacklist().revoke_token(token)

        # Subsequent request with the same token should get 401
        resp = client.get("/api/users", headers=headers)
        assert resp.status_code == 401
        data = resp.get_json()
        assert "revoked" in data["detail"].lower()

    def test_other_tokens_still_work_after_revocation(self, client, admin_service):
        # Use two different users so that tokens always have different
        # signatures (same-user tokens generated in the same second can share
        # the same itsdangerous signature).
        user1 = admin_service.add_user(username="admin1", role=AdminRole.ADMIN)
        user2 = admin_service.add_user(username="admin2", role=AdminRole.ADMIN)
        token1 = _bearer_token(user1)
        token2 = _bearer_token(user2)

        # Revoke only token1
        get_token_blacklist().revoke_token(token1)

        resp1 = client.get("/api/users", headers={"Authorization": f"Bearer {token1}"})
        assert resp1.status_code == 401

        resp2 = client.get("/api/users", headers={"Authorization": f"Bearer {token2}"})
        assert resp2.status_code == 200


# ---------------------------------------------------------------------------
# Integration tests — logout endpoint
# ---------------------------------------------------------------------------


class TestLogoutEndpoint:
    """test_logout_endpoint:
    POST /auth/logout revokes the token and subsequent requests fail.
    """

    def test_logout_endpoint(self, client, admin_service):
        user = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        token = _bearer_token(user)
        headers = {"Authorization": f"Bearer {token}"}

        # Verify token works before logout
        resp = client.get("/api/users", headers=headers)
        assert resp.status_code == 200

        # Logout
        resp = client.post("/api/auth/logout", headers=headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "logged_out"

        # Same token should now be rejected
        resp = client.get("/api/users", headers=headers)
        assert resp.status_code == 401

    def test_logout_without_auth_returns_401(self, client):
        resp = client.post("/api/auth/logout")
        assert resp.status_code == 401

    def test_logout_with_invalid_token_returns_401(self, client):
        resp = client.post(
            "/api/auth/logout",
            headers={"Authorization": "Bearer totally-invalid-token"},
        )
        assert resp.status_code == 401

    def test_logout_idempotent(self, client, admin_service):
        """Logging out with an already-revoked token returns 401 (not 200)."""
        user = admin_service.add_user(username="admin", role=AdminRole.ADMIN)
        token = _bearer_token(user)
        headers = {"Authorization": f"Bearer {token}"}

        # First logout succeeds
        resp = client.post("/api/auth/logout", headers=headers)
        assert resp.status_code == 200

        # Second logout with same token is rejected (already revoked)
        resp = client.post("/api/auth/logout", headers=headers)
        assert resp.status_code == 401

    def test_logout_does_not_affect_other_tokens(self, client, admin_service):
        # Use two different users so tokens have distinct signatures
        # (same-user tokens generated in the same second share the same
        # itsdangerous signature).
        user1 = admin_service.add_user(username="admin1", role=AdminRole.ADMIN)
        user2 = admin_service.add_user(username="admin2", role=AdminRole.ADMIN)
        token1 = _bearer_token(user1)
        token2 = _bearer_token(user2)

        # Logout token1
        resp = client.post(
            "/api/auth/logout",
            headers={"Authorization": f"Bearer {token1}"},
        )
        assert resp.status_code == 200

        # token2 still works
        resp = client.get(
            "/api/users",
            headers={"Authorization": f"Bearer {token2}"},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Module singleton test
# ---------------------------------------------------------------------------


class TestGetTokenBlacklist:
    """Verify the module-level singleton accessor."""

    def test_returns_same_instance(self):
        bl1 = get_token_blacklist()
        bl2 = get_token_blacklist()
        assert bl1 is bl2

    def test_is_token_blacklist_instance(self):
        bl = get_token_blacklist()
        assert isinstance(bl, TokenBlacklist)
