"""Sensitive data sanitization for log output.

Provides :func:`sanitize_for_logs` which redacts cryptographic material
(JWK key values, PEM bodies, CSR DER) from data structures before they
are written to log files or audit tables.  Only metadata (key type,
curve, subject) is preserved.
"""

from __future__ import annotations

import re
from typing import Any

# JWK fields that contain raw key material
_JWK_SECRET_FIELDS = frozenset({"n", "e", "x", "y", "d", "p", "q", "dp", "dq", "qi", "k"})

# Regex matching the base64 body inside PEM blocks
_PEM_BODY_RE = re.compile(
    r"(-----BEGIN [A-Z0-9 ]+-----)"
    r"([\s\S]*?)"
    r"(-----END [A-Z0-9 ]+-----)",
)


def sanitize_jwk(jwk: dict) -> dict:
    """Return a copy of *jwk* with key material replaced by ``[REDACTED]``.

    Preserves ``kty``, ``crv``, ``use``, ``alg``, ``kid``, and ``key_ops``
    for diagnostic context.
    """
    result = {}
    for key, value in jwk.items():
        if key in _JWK_SECRET_FIELDS:
            result[key] = "[REDACTED]"
        else:
            result[key] = value
    return result


def sanitize_pem(pem: str) -> str:
    """Replace the base64 body of PEM blocks with ``[REDACTED]``.

    Preserves BEGIN/END markers so the type of object is still visible.
    """

    def _redact(m) -> str:
        return f"{m.group(1)}\n[REDACTED]\n{m.group(3)}"

    return _PEM_BODY_RE.sub(_redact, pem)


def sanitize_for_logs(data: Any) -> Any:
    """Recursively sanitize sensitive material in *data*.

    Handles dicts (JWK-like structures, PEM strings in values),
    lists, and plain strings.  Non-sensitive data passes through
    unchanged.
    """
    if isinstance(data, dict):
        # Detect JWK-like dicts by presence of "kty"
        if "kty" in data:
            return sanitize_jwk(data)
        return {k: sanitize_for_logs(v) for k, v in data.items()}

    if isinstance(data, (list, tuple)):
        return type(data)(sanitize_for_logs(item) for item in data)

    if isinstance(data, str):
        if "-----BEGIN " in data:
            return sanitize_pem(data)
        return data

    return data
