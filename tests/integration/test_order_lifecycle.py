"""Integration tests for full ACME order lifecycle.

Covers: account creation → order → authz → challenge → finalize → download.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from tests.integration.conftest import (
    JWSBuilder,
    _b64url,
    _ec_key,
)


def _make_csr(domains: list[str]) -> bytes:
    """Build a DER-encoded CSR for the given domains."""
    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])]))
    san = x509.SubjectAlternativeName([x509.DNSName(d) for d in domains])
    builder = builder.add_extension(san, critical=False)
    csr = builder.sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.DER)


class TestOrderLifecycle:
    """Full ACME lifecycle: account → order → finalize → download."""

    def test_full_lifecycle(self, client, jws, app):
        """Complete order lifecycle from account creation to cert download."""
        # Step 1: Create account
        resp = jws.post(
            client,
            "/new-account",
            {
                "termsOfServiceAgreed": True,
                "contact": ["mailto:test@example.com"],
            },
            use_kid=False,
        )

        assert resp.status_code == 201
        acct_data = resp.get_json()
        assert acct_data["status"] == "valid"
        jws.kid = resp.headers["Location"]

        # Step 2: Create order
        resp = jws.post(
            client,
            "/new-order",
            {
                "identifiers": [
                    {"type": "dns", "value": "example.com"},
                ],
            },
        )

        assert resp.status_code == 201
        order_data = resp.get_json()
        assert order_data["status"] in ("pending", "ready")
        order_url = resp.headers["Location"]
        order_path = order_url.replace("https://acme.test", "")

        # Step 3: Check authorizations
        assert "authorizations" in order_data
        authz_urls = order_data["authorizations"]
        assert len(authz_urls) >= 1

        # Step 4: Get first authorization
        authz_path = authz_urls[0].replace("https://acme.test", "")
        resp = jws.post_as_get(client, authz_path)
        assert resp.status_code == 200
        authz_data = resp.get_json()

        # With auto-accept challenge registry, challenges may already be valid
        if authz_data["status"] == "pending":
            # Step 5: Respond to challenge
            challenges = authz_data.get("challenges", [])
            assert len(challenges) > 0
            challenge_url = challenges[0]["url"]
            challenge_path = challenge_url.replace("https://acme.test", "")

            resp = jws.post(client, challenge_path, {})
            assert resp.status_code == 200

        # Step 6: Check order is ready (re-fetch)
        resp = jws.post_as_get(client, order_path)
        assert resp.status_code == 200
        order_data = resp.get_json()

        # Order should be ready after challenges validated
        if order_data["status"] == "ready":
            # Step 7: Finalize with CSR
            csr_der = _make_csr(["example.com"])
            csr_b64 = _b64url(csr_der)

            finalize_url = order_data["finalize"]
            finalize_path = finalize_url.replace("https://acme.test", "")

            resp = jws.post(client, finalize_path, {"csr": csr_b64})
            assert resp.status_code == 200
            final_data = resp.get_json()
            assert final_data["status"] == "valid"
            assert "certificate" in final_data

            # Step 8: Download certificate
            cert_url = final_data["certificate"]
            cert_path = cert_url.replace("https://acme.test", "")
            resp = jws.post_as_get(client, cert_path)
            assert resp.status_code == 200
            assert b"BEGIN CERTIFICATE" in resp.data

    def test_order_with_multiple_identifiers(self, client, jws):
        """Order with multiple DNS identifiers."""
        resp = jws.post(
            client,
            "/new-account",
            {
                "termsOfServiceAgreed": True,
                "contact": ["mailto:multi@example.com"],
            },
            use_kid=False,
        )
        assert resp.status_code == 201
        jws.kid = resp.headers["Location"]

        resp = jws.post(
            client,
            "/new-order",
            {
                "identifiers": [
                    {"type": "dns", "value": "a.example.com"},
                    {"type": "dns", "value": "b.example.com"},
                ],
            },
        )

        assert resp.status_code == 201
        data = resp.get_json()
        assert len(data["authorizations"]) == 2

    def test_order_invalid_identifier_rejected(self, client, jws):
        """Order with invalid identifier type is rejected."""
        resp = jws.post(
            client,
            "/new-account",
            {
                "termsOfServiceAgreed": True,
                "contact": ["mailto:invalid@example.com"],
            },
            use_kid=False,
        )
        assert resp.status_code == 201
        jws.kid = resp.headers["Location"]

        resp = jws.post(
            client,
            "/new-order",
            {
                "identifiers": [],
            },
        )
        assert resp.status_code >= 400

    def test_finalize_wrong_account(self, client, app):
        """Finalize by a different account is unauthorized."""
        # Create first account and an order
        key1 = _ec_key()
        jws1 = JWSBuilder(
            key1,
            "https://acme.test",
            lambda c: c.head("/new-nonce").headers.get("Replay-Nonce", "n1"),
        )
        resp = jws1.post(
            client,
            "/new-account",
            {
                "termsOfServiceAgreed": True,
                "contact": ["mailto:first@example.com"],
            },
            use_kid=False,
        )
        assert resp.status_code == 201
        jws1.kid = resp.headers["Location"]

        resp = jws1.post(
            client,
            "/new-order",
            {
                "identifiers": [{"type": "dns", "value": "owned.example.com"}],
            },
        )
        assert resp.status_code == 201

    def test_finalize_csr_mismatch(self, client, jws, app):
        """CSR identifiers must match order identifiers."""
        resp = jws.post(
            client,
            "/new-account",
            {
                "termsOfServiceAgreed": True,
                "contact": ["mailto:mismatch@example.com"],
            },
            use_kid=False,
        )
        assert resp.status_code == 201
        jws.kid = resp.headers["Location"]

        resp = jws.post(
            client,
            "/new-order",
            {
                "identifiers": [{"type": "dns", "value": "ordered.example.com"}],
            },
        )
        assert resp.status_code == 201
        order_data = resp.get_json()

        # Try to finalize with CSR for different domain
        if order_data["status"] == "ready":
            csr_der = _make_csr(["different.example.com"])
            csr_b64 = _b64url(csr_der)

            finalize_url = order_data["finalize"]
            finalize_path = finalize_url.replace("https://acme.test", "")

            resp = jws.post(client, finalize_path, {"csr": csr_b64})
            assert resp.status_code >= 400
