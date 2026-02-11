"""Tests for multi-account scenarios on the same domain.

Verifies that two different ACME accounts can independently create orders,
challenges, and authorizations for the same domain without interfering
with each other.
"""

from __future__ import annotations

from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from tests.integration.conftest import (
    JWSBuilder,
    _b64url,
    _ec_key,
)


def _make_csr_der(domains: list[str]) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])]))
    san = x509.SubjectAlternativeName([x509.DNSName(d) for d in domains])
    builder = builder.add_extension(san, critical=False)
    csr = builder.sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.DER)


def _get_nonce(client):
    resp = client.head("/new-nonce")
    return resp.headers.get("Replay-Nonce", "test-" + uuid4().hex)


class TestMultiAccountSameDomain:
    """Two accounts challenge the same domain independently."""

    SHARED_DOMAIN = "shared.example.com"

    def _create_account(self, client):
        """Create an account and return a JWSBuilder with kid set."""
        key = _ec_key()
        jws = JWSBuilder(key, "https://acme.test", _get_nonce)

        resp = jws.post(
            client,
            "/new-account",
            {
                "termsOfServiceAgreed": True,
                "contact": [f"mailto:user-{uuid4().hex[:8]}@example.com"],
            },
            use_kid=False,
        )
        assert resp.status_code == 201, f"Account creation failed: {resp.data}"
        jws.kid = resp.headers["Location"]
        return jws

    def test_two_accounts_create_orders_for_same_domain(self, client, app):
        """Both accounts should be able to create orders for the same domain."""
        jws1 = self._create_account(client)
        jws2 = self._create_account(client)

        # Both create orders for the same domain
        resp1 = jws1.post(
            client,
            "/new-order",
            {
                "identifiers": [{"type": "dns", "value": self.SHARED_DOMAIN}],
            },
        )
        resp2 = jws2.post(
            client,
            "/new-order",
            {
                "identifiers": [{"type": "dns", "value": self.SHARED_DOMAIN}],
            },
        )

        assert resp1.status_code == 201
        assert resp2.status_code == 201

        order1 = resp1.get_json()
        order2 = resp2.get_json()

        # Orders should be distinct (different URLs)
        loc1 = resp1.headers["Location"]
        loc2 = resp2.headers["Location"]
        assert loc1 != loc2, "Each account should get a distinct order"

        # Both orders should have the same identifier
        assert order1["identifiers"] == order2["identifiers"]

    def test_two_accounts_have_independent_authorizations(self, client, app):
        """Each account gets separate authorization objects."""
        jws1 = self._create_account(client)
        jws2 = self._create_account(client)

        resp1 = jws1.post(
            client,
            "/new-order",
            {
                "identifiers": [{"type": "dns", "value": self.SHARED_DOMAIN}],
            },
        )
        resp2 = jws2.post(
            client,
            "/new-order",
            {
                "identifiers": [{"type": "dns", "value": self.SHARED_DOMAIN}],
            },
        )

        assert resp1.status_code == 201
        assert resp2.status_code == 201

        authz1 = resp1.get_json()["authorizations"]
        authz2 = resp2.get_json()["authorizations"]

        # Authorizations should be separate URLs
        assert set(authz1).isdisjoint(set(authz2)), (
            "Authorizations should not be shared across accounts"
        )

    def test_account1_cannot_access_account2_order(self, client, app):
        """Account 1 cannot retrieve Account 2's order."""
        jws1 = self._create_account(client)
        jws2 = self._create_account(client)

        # Account 2 creates an order
        resp2 = jws2.post(
            client,
            "/new-order",
            {
                "identifiers": [{"type": "dns", "value": self.SHARED_DOMAIN}],
            },
        )
        assert resp2.status_code == 201
        order2_url = resp2.headers["Location"]
        order2_path = order2_url.replace("https://acme.test", "")

        # Account 1 tries to access Account 2's order
        resp = jws1.post_as_get(client, order2_path)
        assert resp.status_code in (403, 401), f"Expected 403 or 401, got {resp.status_code}"

    def test_both_accounts_can_finalize_independently(self, client, app):
        """Both accounts can independently finalize their orders."""
        jws1 = self._create_account(client)
        jws2 = self._create_account(client)

        domain = "multi-finalize.example.com"

        # Both create orders
        resp1 = jws1.post(
            client,
            "/new-order",
            {
                "identifiers": [{"type": "dns", "value": domain}],
            },
        )
        resp2 = jws2.post(
            client,
            "/new-order",
            {
                "identifiers": [{"type": "dns", "value": domain}],
            },
        )

        assert resp1.status_code == 201
        assert resp2.status_code == 201

        order1 = resp1.get_json()
        order2 = resp2.get_json()

        # If orders are ready, try to finalize both
        if order1["status"] == "ready" and order2["status"] == "ready":
            csr1 = _make_csr_der([domain])
            csr2 = _make_csr_der([domain])

            finalize1 = order1["finalize"].replace("https://acme.test", "")
            finalize2 = order2["finalize"].replace("https://acme.test", "")

            r1 = jws1.post(client, finalize1, {"csr": _b64url(csr1)})
            r2 = jws2.post(client, finalize2, {"csr": _b64url(csr2)})

            assert r1.status_code == 200
            assert r2.status_code == 200

            # Both should get valid orders with certificates
            data1 = r1.get_json()
            data2 = r2.get_json()
            assert data1["status"] == "valid"
            assert data2["status"] == "valid"

            # Certificates should be distinct
            assert data1["certificate"] != data2["certificate"]

    def test_dedup_only_within_same_account(self, client, app):
        """Order deduplication should only apply within the same account."""
        jws1 = self._create_account(client)
        jws2 = self._create_account(client)

        domain = "dedup-test.example.com"

        # Account 1 creates order twice — may get dedup
        r1a = jws1.post(
            client,
            "/new-order",
            {
                "identifiers": [{"type": "dns", "value": domain}],
            },
        )
        r1b = jws1.post(
            client,
            "/new-order",
            {
                "identifiers": [{"type": "dns", "value": domain}],
            },
        )
        assert r1a.status_code == 201
        assert r1b.status_code == 201

        # Account 2 creates same order — should NOT be deduped with account 1
        r2 = jws2.post(
            client,
            "/new-order",
            {
                "identifiers": [{"type": "dns", "value": domain}],
            },
        )
        assert r2.status_code == 201

        loc2 = r2.headers["Location"]
        loc1a = r1a.headers["Location"]
        assert loc2 != loc1a, "Cross-account orders should never be deduped"
