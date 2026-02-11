"""Server-generated password utilities for admin users."""

from __future__ import annotations

import secrets
import string

from werkzeug.security import check_password_hash, generate_password_hash

_UPPER = string.ascii_uppercase
_LOWER = string.ascii_lowercase
_DIGITS = string.digits
_SPECIAL = "!@#$%^&*-_+="
_ALPHABET = _UPPER + _LOWER + _DIGITS + _SPECIAL


def generate_password(length: int = 20) -> str:
    """Generate a cryptographically random password.

    Guarantees at least one character from each category
    (uppercase, lowercase, digit, special) via rejection sampling.
    """
    while True:
        pw = "".join(secrets.choice(_ALPHABET) for _ in range(length))
        if (
            any(c in _UPPER for c in pw)
            and any(c in _LOWER for c in pw)
            and any(c in _DIGITS for c in pw)
            and any(c in _SPECIAL for c in pw)
        ):
            return pw


def hash_password(password: str) -> str:
    """Hash a password for storage."""
    return generate_password_hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    return check_password_hash(password_hash, password)
