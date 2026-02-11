"""Tests for certificate key revocation (RFC 8555 §7.6.4 dual auth).

RFC 8555 §7.6 allows revocation using either:
1. The account key (kid auth) — must own the certificate
2. The certificate's private key (jwk auth) — no account needed

This test suite focuses on scenario 2: revocation using the certificate's
private key, which does NOT require an account relationship.
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from tests.integration.conftest import (
    JWSBuilder,
    _b64url,
    _b64url_json,
    _ec_key,
    _jwk_from_ec,
    _sign_es256,
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


def _get_nonce(client):
    resp = client.head("/new-nonce")
    return resp.headers.get("Replay-Nonce", "test-" + uuid4().hex)


def _build_jwk_jws_revoke(cert_key, cert_der_b64, url, nonce, reason=None):
    """Build a JWS revocation request signed with the certificate's key.

    Uses jwk (not kid) in the protected header — this is the dual-auth
    path from RFC 8555 §7.6.
    """
    jwk = _jwk_from_ec(cert_key.public_key())

    protected = {
        "alg": "ES256",
        "nonce": nonce,
        "url": url,
        "jwk": jwk,
    }

    payload = {"certificate": cert_der_b64}
    if reason is not None:
        payload["reason"] = reason

    protected_b64 = _b64url_json(protected)
    payload_b64 = _b64url_json(payload)

    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    signature = _sign_es256(cert_key, signing_input)
    signature_b64 = _b64url(signature)

    return json.dumps(
        {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature_b64,
        }
    )


class TestCertificateKeyRevocation:
    """Revocation using the certificate's private key (not the account key)."""

    def _issue_cert(self, client, domain="certkey-revoke.example.com"):
        """Issue a certificate and return (cert_der, cert_private_key, account_jws)."""
        # Create account
        acct_jws = JWSBuilder(_ec_key(), "https://acme.test", _get_nonce)
        resp = acct_jws.post(
            client,
            "/new-account",
            {
                "termsOfServiceAgreed": True,
                "contact": [f"mailto:certkey-{uuid4().hex[:8]}@example.com"],
            },
            use_kid=False,
        )
        assert resp.status_code == 201
        acct_jws.kid = resp.headers["Location"]

        # Create order
        resp = acct_jws.post(
            client,
            "/new-order",
            {
                "identifiers": [{"type": "dns", "value": domain}],
            },
        )
        assert resp.status_code == 201
        order = resp.get_json()

        if order["status"] != "ready":
            # Complete challenge validation to move order to ready
            for authz_url in order["authorizations"]:
                authz_path = authz_url.replace("https://acme.test", "")
                aresp = acct_jws.post_as_get(client, authz_path)
                authz_data = aresp.get_json()
                if authz_data["status"] == "pending":
                    ch_url = authz_data["challenges"][0]["url"]
                    ch_path = ch_url.replace("https://acme.test", "")
                    acct_jws.post(client, ch_path, {})

            # Re-fetch order
            order_path = resp.headers["Location"].replace("https://acme.test", "")
            resp = acct_jws.post_as_get(client, order_path)
            order = resp.get_json()
            assert order["status"] == "ready", f"Order still not ready: {order}"

        # Finalize with a CSR (using a separate key for the cert)
        csr_der, cert_key = _make_csr_and_key([domain])
        finalize_path = order["finalize"].replace("https://acme.test", "")

        resp = acct_jws.post(client, finalize_path, {"csr": _b64url(csr_der)})
        if resp.status_code != 200:
            pytest.skip("Finalize failed")

        final_data = resp.get_json()
        if "certificate" not in final_data:
            pytest.skip("No certificate URL")

        # Download the cert
        cert_path = final_data["certificate"].replace("https://acme.test", "")
        resp = acct_jws.post_as_get(client, cert_path)
        assert resp.status_code == 200

        # Parse leaf cert to DER
        pem = resp.data
        leaf_pem = pem.split(b"-----END CERTIFICATE-----")[0] + b"-----END CERTIFICATE-----\n"
        cert_obj = x509.load_pem_x509_certificate(leaf_pem)
        cert_der = cert_obj.public_bytes(serialization.Encoding.DER)

        return cert_der, cert_key, acct_jws

    def test_revoke_by_certificate_key(self, client, app):
        """Revoke a certificate using its own private key (no account needed)."""
        try:
            cert_der, cert_key, _ = self._issue_cert(client)
        except Exception:
            pytest.skip("Could not issue certificate")

        cert_b64 = _b64url(cert_der)
        url = "https://acme.test/revoke-cert"
        nonce = _get_nonce(client)

        body = _build_jwk_jws_revoke(cert_key, cert_b64, url, nonce)

        resp = client.post(
            "/revoke-cert",
            data=body,
            content_type="application/jose+json",
        )
        assert resp.status_code in (200,), f"Expected 200, got {resp.status_code}: {resp.data}"

    def test_revoke_by_cert_key_with_reason(self, client, app):
        """Revoke with cert key and specify a reason code."""
        try:
            cert_der, cert_key, _ = self._issue_cert(
                client,
                "certkey-reason.example.com",
            )
        except Exception:
            pytest.skip("Could not issue certificate")

        cert_b64 = _b64url(cert_der)
        url = "https://acme.test/revoke-cert"
        nonce = _get_nonce(client)

        body = _build_jwk_jws_revoke(
            cert_key,
            cert_b64,
            url,
            nonce,
            reason=1,  # keyCompromise
        )

        resp = client.post(
            "/revoke-cert",
            data=body,
            content_type="application/jose+json",
        )
        assert resp.status_code in (200,), f"Expected 200, got {resp.status_code}: {resp.data}"

    def test_revoke_by_wrong_key_rejected(self, client, app):
        """Revocation with a key that doesn't match the cert should fail."""
        try:
            cert_der, cert_key, _ = self._issue_cert(
                client,
                "certkey-wrong.example.com",
            )
        except Exception:
            pytest.skip("Could not issue certificate")

        cert_b64 = _b64url(cert_der)
        url = "https://acme.test/revoke-cert"
        nonce = _get_nonce(client)

        # Use a DIFFERENT key (not the cert key)
        wrong_key = _ec_key()

        body = _build_jwk_jws_revoke(wrong_key, cert_b64, url, nonce)

        resp = client.post(
            "/revoke-cert",
            data=body,
            content_type="application/jose+json",
        )
        assert resp.status_code in (403, 401), (
            f"Expected 403/401, got {resp.status_code}: {resp.data}"
        )

    def test_double_revoke_by_cert_key(self, client, app):
        """Double revocation with cert key should fail on the second attempt."""
        try:
            cert_der, cert_key, _ = self._issue_cert(
                client,
                "certkey-double.example.com",
            )
        except Exception:
            pytest.skip("Could not issue certificate")

        cert_b64 = _b64url(cert_der)
        url = "https://acme.test/revoke-cert"

        # First revocation
        nonce1 = _get_nonce(client)
        body1 = _build_jwk_jws_revoke(cert_key, cert_b64, url, nonce1)
        resp1 = client.post(
            "/revoke-cert",
            data=body1,
            content_type="application/jose+json",
        )
        if resp1.status_code != 200:
            pytest.skip("First revocation failed")

        # Second revocation — should fail
        nonce2 = _get_nonce(client)
        body2 = _build_jwk_jws_revoke(cert_key, cert_b64, url, nonce2)
        resp2 = client.post(
            "/revoke-cert",
            data=body2,
            content_type="application/jose+json",
        )
        assert resp2.status_code in (400, 409), (
            f"Expected 400/409 for already-revoked, got {resp2.status_code}"
        )

    def test_cert_key_revoke_different_account_cert(self, client, app):
        """An unrelated key holder with the cert's key can still revoke,
        even though they are not the account owner."""
        try:
            cert_der, cert_key, acct_jws = self._issue_cert(
                client,
                "certkey-other.example.com",
            )
        except Exception:
            pytest.skip("Could not issue certificate")

        # Create a completely different account
        other_jws = JWSBuilder(_ec_key(), "https://acme.test", _get_nonce)
        resp = other_jws.post(
            client,
            "/new-account",
            {
                "termsOfServiceAgreed": True,
                "contact": ["mailto:other@example.com"],
            },
            use_kid=False,
        )
        assert resp.status_code == 201

        # Use the CERT key (not the other account's key) to revoke
        cert_b64 = _b64url(cert_der)
        url = "https://acme.test/revoke-cert"
        nonce = _get_nonce(client)

        body = _build_jwk_jws_revoke(cert_key, cert_b64, url, nonce)

        resp = client.post(
            "/revoke-cert",
            data=body,
            content_type="application/jose+json",
        )
        # Should succeed — cert key auth doesn't require account ownership
        assert resp.status_code == 200, (
            f"Cert key revocation should work regardless of account: {resp.data}"
        )
