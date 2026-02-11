"""Tests for admin token management."""

from __future__ import annotations

import time
from uuid import uuid4

from acmeeh.admin.auth import create_token, decode_token
from acmeeh.admin.models import AdminUser
from acmeeh.core.types import AdminRole


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


class TestTokenCreateDecode:
    def test_roundtrip(self):
        user = _make_user()
        secret = "test-secret-key-12345"
        token = create_token(user, secret, max_age=3600)
        payload = decode_token(token, secret, max_age=3600)

        assert payload is not None
        assert payload["user_id"] == str(user.id)
        assert payload["username"] == user.username
        assert payload["role"] == user.role.value

    def test_wrong_secret_returns_none(self):
        user = _make_user()
        token = create_token(user, "secret-a", max_age=3600)
        payload = decode_token(token, "secret-b", max_age=3600)
        assert payload is None

    def test_tampered_token_returns_none(self):
        user = _make_user()
        secret = "test-secret"
        token = create_token(user, secret, max_age=3600)
        tampered = token[:-5] + "XXXXX"
        payload = decode_token(tampered, secret, max_age=3600)
        assert payload is None

    def test_expired_token_returns_none(self):
        user = _make_user()
        secret = "test-secret"
        token = create_token(user, secret, max_age=1)
        time.sleep(2)
        payload = decode_token(token, secret, max_age=1)
        assert payload is None

    def test_different_users_different_tokens(self):
        secret = "test-secret"
        user1 = _make_user(username="user1")
        user2 = _make_user(username="user2")
        t1 = create_token(user1, secret, max_age=3600)
        t2 = create_token(user2, secret, max_age=3600)
        assert t1 != t2

    def test_role_preserved(self):
        secret = "test-secret"
        user = _make_user(role=AdminRole.AUDITOR)
        token = create_token(user, secret, max_age=3600)
        payload = decode_token(token, secret, max_age=3600)
        assert payload["role"] == "auditor"
