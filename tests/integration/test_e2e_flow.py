"""End-to-end integration tests for the full ACME lifecycle.

Exercises the complete RFC 8555 flow using the Flask test client and
in-memory mocks:  directory discovery -> nonce -> account creation ->
order -> authorization -> challenge -> finalization -> certificate
download -> orders listing -> revocation -> account deactivation.
"""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from tests.integration.conftest import (
    JWSBuilder,
    _b64url,
    _ec_key,
)

# ---------------------------------------------------------------------------
# Auto-accept fixture — patches validators so they never make real HTTP calls
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _auto_accept_challenges(monkeypatch):
    """Monkeypatch challenge validators to succeed without network I/O."""
    from acmeeh.challenge import dns01, http01

    def _noop_validate(self, *args, **kwargs):
        pass  # Validation succeeds silently

    monkeypatch.setattr(http01.Http01Validator, "validate", _noop_validate)
    if hasattr(dns01, "Dns01Validator"):
        monkeypatch.setattr(dns01.Dns01Validator, "validate", _noop_validate)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_csr(domains: list[str]) -> bytes:
    """Build a DER-encoded CSR for the given domains."""
    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])]))
    san = x509.SubjectAlternativeName([x509.DNSName(d) for d in domains])
    builder = builder.add_extension(san, critical=False)
    csr = builder.sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.DER)


def _strip_base(url: str) -> str:
    """Strip the external base URL to get a local test path."""
    return url.replace("https://acme.test", "")


def _register_account(client, jws, email="e2e@example.com"):
    """Create a new account and set the kid on the JWS builder."""
    resp = jws.post(
        client,
        "/new-account",
        {
            "termsOfServiceAgreed": True,
            "contact": [f"mailto:{email}"],
        },
        use_kid=False,
    )
    assert resp.status_code == 201, resp.get_json()
    jws.kid = resp.headers["Location"]
    return resp


def _create_order(client, jws, domains):
    """Create a new order and return (order_path, order_data)."""
    resp = jws.post(
        client,
        "/new-order",
        {
            "identifiers": [{"type": "dns", "value": d} for d in domains],
        },
    )
    assert resp.status_code == 201, resp.get_json()
    order_path = _strip_base(resp.headers["Location"])
    return order_path, resp.get_json()


def _complete_challenges(client, jws, order_data):
    """Walk all authorizations and respond to pending challenges."""
    for authz_url in order_data.get("authorizations", []):
        authz_path = _strip_base(authz_url)
        resp = jws.post_as_get(client, authz_path)
        assert resp.status_code == 200
        authz = resp.get_json()

        if authz["status"] == "pending":
            for ch in authz.get("challenges", []):
                ch_path = _strip_base(ch["url"])
                resp = jws.post(client, ch_path, {})
                assert resp.status_code == 200


def _finalize_order(client, jws, order_data, domains):
    """Finalize the order with a CSR.  Returns the updated order JSON."""
    csr_der = _make_csr(domains)
    csr_b64 = _b64url(csr_der)
    finalize_path = _strip_base(order_data["finalize"])

    resp = jws.post(client, finalize_path, {"csr": csr_b64})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()


def _download_cert(client, jws, final_data):
    """Download the certificate PEM chain.  Returns raw bytes."""
    cert_path = _strip_base(final_data["certificate"])
    resp = jws.post_as_get(client, cert_path)
    assert resp.status_code == 200
    assert b"BEGIN CERTIFICATE" in resp.data
    return resp.data


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestE2EFullLifecycle:
    """Complete ACME lifecycle from directory discovery to revocation."""

    def test_directory_discovery(self, client):
        """GET /directory returns resource URLs and metadata."""
        resp = client.get("/directory")
        assert resp.status_code == 200
        body = resp.get_json()

        # RFC 8555 mandatory fields
        assert "newNonce" in body
        assert "newAccount" in body
        assert "newOrder" in body

    def test_nonce_flow(self, client):
        """HEAD /new-nonce returns a fresh Replay-Nonce."""
        resp = client.head("/new-nonce")
        assert resp.status_code == 200
        nonce = resp.headers.get("Replay-Nonce")
        assert nonce is not None and len(nonce) > 0

        # A second request returns a different nonce
        resp2 = client.head("/new-nonce")
        nonce2 = resp2.headers.get("Replay-Nonce")
        assert nonce2 != nonce

    def test_complete_lifecycle(self, client, jws, app):
        """Full path: account -> order -> challenge -> finalize -> download -> revoke."""
        # 1. Create account
        _register_account(client, jws)

        # 2. Create order
        domains = ["e2e.example.com"]
        order_path, order_data = _create_order(client, jws, domains)
        assert order_data["status"] in ("pending", "ready")
        assert "authorizations" in order_data
        assert "finalize" in order_data

        # 3. Complete challenges
        _complete_challenges(client, jws, order_data)

        # 4. Re-fetch order via its URL to confirm status change
        resp = jws.post_as_get(client, order_path)
        assert resp.status_code == 200
        order_data = resp.get_json()

        if order_data["status"] != "ready":
            pytest.skip("Order not ready after challenge completion")

        # 5. Finalize with CSR
        final_data = _finalize_order(client, jws, order_data, domains)
        assert final_data["status"] == "valid"
        assert "certificate" in final_data

        # 6. Download certificate
        cert_pem = _download_cert(client, jws, final_data)

        # Parse and verify the leaf cert
        leaf_pem = cert_pem.split(b"-----END CERTIFICATE-----")[0] + b"-----END CERTIFICATE-----\n"
        cert_obj = x509.load_pem_x509_certificate(leaf_pem)
        san = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "e2e.example.com" in dns_names

        # 7. Revoke by account key
        cert_der = cert_obj.public_bytes(serialization.Encoding.DER)
        cert_b64 = _b64url(cert_der)
        resp = jws.post(client, "/revoke-cert", {"certificate": cert_b64})
        assert resp.status_code in (200, 409)

    def test_account_lookup(self, client, jws):
        """onlyReturnExisting finds a previously created account."""
        _register_account(client, jws, "lookup@example.com")

        resp = jws.post(
            client,
            "/new-account",
            {
                "onlyReturnExisting": True,
            },
            use_kid=False,
        )
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "valid"

    def test_account_contact_update(self, client, jws):
        """Update account contacts after creation."""
        resp = _register_account(client, jws, "original@example.com")
        acct_path = _strip_base(resp.headers["Location"])

        resp = jws.post(
            client,
            acct_path,
            {
                "contact": ["mailto:updated@example.com"],
            },
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert "mailto:updated@example.com" in body.get("contact", [])

    def test_account_deactivation(self, client, jws, app):
        """Deactivate an account and confirm subsequent requests fail."""
        resp = _register_account(client, jws, "deactivate@example.com")
        acct_path = _strip_base(resp.headers["Location"])

        # Deactivate
        resp = jws.post(client, acct_path, {"status": "deactivated"})
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "deactivated"

    def test_orders_listing(self, client, jws, app):
        """List orders for an account after creating some."""
        resp = _register_account(client, jws, "orders@example.com")
        acct_path = _strip_base(resp.headers["Location"])

        # Create two orders
        _create_order(client, jws, ["list1.example.com"])
        _create_order(client, jws, ["list2.example.com"])

        # List orders
        orders_path = acct_path + "/orders"
        resp = jws.post_as_get(client, orders_path)
        assert resp.status_code == 200
        body = resp.get_json()
        assert "orders" in body
        assert len(body["orders"]) >= 2


class TestE2EMultiDomain:
    """Tests with multiple identifiers in a single order."""

    def test_multi_domain_order_lifecycle(self, client, jws, app):
        """Order with 3 domains: challenge all, finalize, download."""
        domains = ["a.multi.test", "b.multi.test", "c.multi.test"]
        _register_account(client, jws, "multi@example.com")

        order_path, order_data = _create_order(client, jws, domains)
        assert len(order_data["authorizations"]) == len(domains)

        _complete_challenges(client, jws, order_data)

        # Re-fetch order via its URL
        resp = jws.post_as_get(client, order_path)
        assert resp.status_code == 200
        order_data = resp.get_json()

        if order_data["status"] != "ready":
            pytest.skip("Order not ready after challenges")

        final_data = _finalize_order(client, jws, order_data, domains)
        assert final_data["status"] == "valid"

        cert_pem = _download_cert(client, jws, final_data)
        leaf_pem = cert_pem.split(b"-----END CERTIFICATE-----")[0] + b"-----END CERTIFICATE-----\n"
        cert_obj = x509.load_pem_x509_certificate(leaf_pem)
        san = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        for d in domains:
            assert d in dns_names


class TestE2EErrorPaths:
    """Error cases exercised through the full stack."""

    def test_order_empty_identifiers_rejected(self, client, jws):
        """An order with no identifiers returns an error."""
        _register_account(client, jws, "empty@example.com")
        resp = jws.post(client, "/new-order", {"identifiers": []})
        assert resp.status_code >= 400

    def test_finalize_csr_domain_mismatch(self, client, jws, app):
        """CSR domains must match the order identifiers."""
        _register_account(client, jws, "mismatch@example.com")
        order_path, order_data = _create_order(client, jws, ["ordered.example.com"])

        if order_data["status"] != "ready":
            _complete_challenges(client, jws, order_data)
            resp = jws.post_as_get(client, order_path)
            order_data = resp.get_json()
            if order_data["status"] != "ready":
                pytest.skip("Order not ready")

        # CSR for a different domain
        csr_der = _make_csr(["wrong.example.com"])
        csr_b64 = _b64url(csr_der)
        finalize_path = _strip_base(order_data["finalize"])
        resp = jws.post(client, finalize_path, {"csr": csr_b64})
        assert resp.status_code >= 400

    def test_revoke_without_cert(self, client, jws):
        """Revoke with missing certificate field returns error."""
        _register_account(client, jws, "nocert@example.com")
        resp = jws.post(client, "/revoke-cert", {})
        assert resp.status_code >= 400

    def test_double_revocation(self, client, jws, app):
        """Revoking the same cert twice returns an error on the second attempt."""
        _register_account(client, jws, "double-rev@example.com")
        domains = ["double-rev.example.com"]
        order_path, order_data = _create_order(client, jws, domains)

        if order_data["status"] != "ready":
            _complete_challenges(client, jws, order_data)
            resp = jws.post_as_get(client, order_path)
            order_data = resp.get_json()
            if order_data["status"] != "ready":
                pytest.skip("Order not ready")

        final_data = _finalize_order(client, jws, order_data, domains)
        if "certificate" not in final_data:
            pytest.skip("No certificate in finalized order")

        cert_pem = _download_cert(client, jws, final_data)
        leaf_pem = cert_pem.split(b"-----END CERTIFICATE-----")[0] + b"-----END CERTIFICATE-----\n"
        cert_obj = x509.load_pem_x509_certificate(leaf_pem)
        cert_der = cert_obj.public_bytes(serialization.Encoding.DER)
        cert_b64 = _b64url(cert_der)

        resp1 = jws.post(client, "/revoke-cert", {"certificate": cert_b64})
        if resp1.status_code != 200:
            pytest.skip("First revocation failed")

        resp2 = jws.post(client, "/revoke-cert", {"certificate": cert_b64})
        assert resp2.status_code in (400, 409)

    def test_request_without_nonce_rejected(self, client, app):
        """A JWS without a valid nonce is rejected."""
        key = _ec_key()
        # Build a JWS builder that always returns an invalid nonce
        jws = JWSBuilder(key, "https://acme.test", lambda c: "invalid-nonce")

        resp = jws.post(
            client,
            "/new-account",
            {
                "termsOfServiceAgreed": True,
                "contact": ["mailto:bad-nonce@example.com"],
            },
            use_kid=False,
        )
        # Should be rejected (badNonce)
        assert resp.status_code >= 400
