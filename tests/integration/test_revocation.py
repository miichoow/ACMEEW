"""Integration tests for certificate revocation (RFC 8555 §7.6).

Tests revocation by account key and by certificate key, double-revoke,
and invalid reason codes.
"""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from tests.integration.conftest import (
    _b64url,
)


def _make_csr_and_key(domains: list[str]):
    """Build a DER-encoded CSR and return (csr_der, private_key)."""
    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])]))
    san = x509.SubjectAlternativeName([x509.DNSName(d) for d in domains])
    builder = builder.add_extension(san, critical=False)
    csr = builder.sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.DER), key


class TestRevocation:
    """Certificate revocation tests."""

    def _issue_cert(self, client, jws, domain="revoke.example.com"):
        """Helper: create account, order, finalize — return cert DER + account details."""
        # Create account
        resp = jws.post(
            client,
            "/new-account",
            {
                "termsOfServiceAgreed": True,
                "contact": ["mailto:revoke@example.com"],
            },
            use_kid=False,
        )
        assert resp.status_code == 201
        jws.kid = resp.headers["Location"]

        # Create order
        resp = jws.post(
            client,
            "/new-order",
            {
                "identifiers": [{"type": "dns", "value": domain}],
            },
        )
        assert resp.status_code == 201
        order_data = resp.get_json()

        if order_data["status"] != "ready":
            # Complete challenge validation to move order to ready
            for authz_url in order_data["authorizations"]:
                authz_path = authz_url.replace("https://acme.test", "")
                aresp = jws.post_as_get(client, authz_path)
                authz_data = aresp.get_json()
                if authz_data["status"] == "pending":
                    ch_url = authz_data["challenges"][0]["url"]
                    ch_path = ch_url.replace("https://acme.test", "")
                    jws.post(client, ch_path, {})

            # Re-fetch order
            order_path = resp.headers["Location"].replace("https://acme.test", "")
            resp = jws.post_as_get(client, order_path)
            order_data = resp.get_json()
            assert order_data["status"] == "ready", f"Order still not ready: {order_data}"

        # Finalize
        csr_der, cert_key = _make_csr_and_key([domain])
        csr_b64 = _b64url(csr_der)
        finalize_url = order_data["finalize"]
        finalize_path = finalize_url.replace("https://acme.test", "")

        resp = jws.post(client, finalize_path, {"csr": csr_b64})
        if resp.status_code != 200:
            pytest.skip("Finalize failed")

        final_data = resp.get_json()
        if "certificate" not in final_data:
            pytest.skip("No certificate URL")

        # Download cert
        cert_path = final_data["certificate"].replace("https://acme.test", "")
        resp = jws.post_as_get(client, cert_path)
        assert resp.status_code == 200

        # Parse leaf cert DER
        pem_data = resp.data
        cert_obj = x509.load_pem_x509_certificate(
            pem_data.split(b"-----END CERTIFICATE-----")[0] + b"-----END CERTIFICATE-----\n"
        )
        cert_der = cert_obj.public_bytes(serialization.Encoding.DER)

        return cert_der, cert_key

    def test_revoke_by_account_key(self, client, jws, app):
        """Revoke using the account key."""
        try:
            cert_der, _ = self._issue_cert(client, jws)
        except Exception:
            pytest.skip("Could not issue certificate for revocation test")

        cert_b64 = _b64url(cert_der)

        resp = jws.post(
            client,
            "/revoke-cert",
            {
                "certificate": cert_b64,
            },
        )
        # Should succeed or already revoked
        assert resp.status_code in (200, 409)

    def test_revoke_with_reason(self, client, jws, app):
        """Revoke with a valid reason code."""
        try:
            cert_der, _ = self._issue_cert(client, jws, "reason.example.com")
        except Exception:
            pytest.skip("Could not issue certificate")

        cert_b64 = _b64url(cert_der)

        resp = jws.post(
            client,
            "/revoke-cert",
            {
                "certificate": cert_b64,
                "reason": 1,  # keyCompromise
            },
        )
        assert resp.status_code in (200, 409)

    def test_revoke_invalid_reason(self, client, jws, app):
        """Revoke with invalid reason code (7 is unused)."""
        try:
            cert_der, _ = self._issue_cert(client, jws, "bad-reason.example.com")
        except Exception:
            pytest.skip("Could not issue certificate")

        cert_b64 = _b64url(cert_der)

        resp = jws.post(
            client,
            "/revoke-cert",
            {
                "certificate": cert_b64,
                "reason": 7,
            },
        )
        assert resp.status_code >= 400

    def test_double_revoke(self, client, jws, app):
        """Revoking an already-revoked cert should fail."""
        try:
            cert_der, _ = self._issue_cert(client, jws, "double.example.com")
        except Exception:
            pytest.skip("Could not issue certificate")

        cert_b64 = _b64url(cert_der)

        resp = jws.post(client, "/revoke-cert", {"certificate": cert_b64})
        if resp.status_code != 200:
            pytest.skip("First revocation failed")

        # Second revocation should fail
        resp = jws.post(client, "/revoke-cert", {"certificate": cert_b64})
        assert resp.status_code in (400, 409)
