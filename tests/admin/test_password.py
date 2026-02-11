"""Tests for admin password generation and hashing."""

from __future__ import annotations

import string

from acmeeh.admin.password import (
    generate_password,
    hash_password,
    verify_password,
)


class TestGeneratePassword:
    def test_default_length(self):
        pw = generate_password()
        assert len(pw) == 20

    def test_custom_length(self):
        pw = generate_password(length=30)
        assert len(pw) == 30

    def test_contains_uppercase(self):
        pw = generate_password()
        assert any(c in string.ascii_uppercase for c in pw)

    def test_contains_lowercase(self):
        pw = generate_password()
        assert any(c in string.ascii_lowercase for c in pw)

    def test_contains_digit(self):
        pw = generate_password()
        assert any(c in string.digits for c in pw)

    def test_contains_special(self):
        pw = generate_password()
        assert any(c in "!@#$%^&*-_+=" for c in pw)

    def test_uniqueness(self):
        passwords = {generate_password() for _ in range(10)}
        assert len(passwords) == 10


class TestPasswordHashing:
    def test_hash_and_verify(self):
        pw = "TestPassword123!"
        hashed = hash_password(pw)
        assert hashed != pw
        assert verify_password(pw, hashed)

    def test_wrong_password_fails(self):
        pw = "TestPassword123!"
        hashed = hash_password(pw)
        assert not verify_password("WrongPassword", hashed)

    def test_different_hashes(self):
        pw = "TestPassword123!"
        h1 = hash_password(pw)
        h2 = hash_password(pw)
        assert h1 != h2  # salted hashes differ
        assert verify_password(pw, h1)
        assert verify_password(pw, h2)
