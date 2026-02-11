"""Integration tests for ACME key change (RFC 8555 §7.3.5).

Tests key rollover with nested JWS.
"""

from __future__ import annotations

from uuid import uuid4

from tests.integration.conftest import (
    JWSBuilder,
    _b64url,
    _b64url_json,
    _ec_key,
    _jwk_from_ec,
    _sign_es256,
)


class TestKeyChange:
    """Key change / key rollover tests."""

    def test_key_change_success(self, client, jws, app):
        """Successfully roll over account key."""
        # Create account
        resp = jws.post(
            client,
            "/new-account",
            {
                "termsOfServiceAgreed": True,
                "contact": ["mailto:keychange@example.com"],
            },
            use_kid=False,
        )
        assert resp.status_code == 201
        jws.kid = resp.headers["Location"]

        # Generate new key
        new_key = _ec_key()
        new_jwk = _jwk_from_ec(new_key.public_key())

        # Build inner JWS for key-change
        inner_payload = {
            "account": jws.kid,
            "oldKey": jws.jwk,
        }
        inner_protected = {
            "alg": "ES256",
            "jwk": new_jwk,
            "url": "https://acme.test/key-change",
        }

        inner_protected_b64 = _b64url_json(inner_protected)
        inner_payload_b64 = _b64url_json(inner_payload)
        inner_signing_input = f"{inner_protected_b64}.{inner_payload_b64}".encode("ascii")
        inner_signature = _sign_es256(new_key, inner_signing_input)
        inner_signature_b64 = _b64url(inner_signature)

        inner_jws = {
            "protected": inner_protected_b64,
            "payload": inner_payload_b64,
            "signature": inner_signature_b64,
        }

        resp = jws.post(client, "/key-change", inner_jws)
        assert resp.status_code == 200

    def test_key_change_no_account(self, client, app):
        """Key change without a valid account fails."""
        key = _ec_key()

        def get_nonce(c):
            resp = c.head("/new-nonce")
            return resp.headers.get("Replay-Nonce", "test-nonce-" + uuid4().hex)

        builder = JWSBuilder(key, "https://acme.test", get_nonce)

        # Try key change without creating account first
        new_key = _ec_key()
        new_jwk = _jwk_from_ec(new_key.public_key())

        inner_payload = {
            "account": "https://acme.test/accounts/nonexistent",
            "oldKey": builder.jwk,
        }
        inner_protected = {
            "alg": "ES256",
            "jwk": new_jwk,
            "url": "https://acme.test/key-change",
        }

        inner_protected_b64 = _b64url_json(inner_protected)
        inner_payload_b64 = _b64url_json(inner_payload)
        inner_signing_input = f"{inner_protected_b64}.{inner_payload_b64}".encode("ascii")
        inner_signature = _sign_es256(new_key, inner_signing_input)

        inner_jws = {
            "protected": inner_protected_b64,
            "payload": inner_payload_b64,
            "signature": _b64url(inner_signature),
        }

        # This should fail because the outer JWS account doesn't exist
        resp = builder.post(client, "/key-change", inner_jws, use_kid=False)
        # Expect an error since account doesn't exist
        assert resp.status_code >= 400
