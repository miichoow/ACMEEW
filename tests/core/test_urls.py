"""Unit tests for acmeeh.core.urls — Centralized URL builder."""

from __future__ import annotations

from types import SimpleNamespace
from uuid import UUID

from acmeeh.core.urls import AcmeUrls

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_settings(
    external_url="https://acme.example.com",
    base_path="/acme",
    ari_enabled=False,
    ari_path="/renewalInfo",
):
    """Build a minimal AcmeehSettings-like object for AcmeUrls."""
    paths = SimpleNamespace(
        directory="/directory",
        new_nonce="/new-nonce",
        new_account="/new-acct",
        new_order="/new-order",
        new_authz="/new-authz",
        revoke_cert="/revoke-cert",
        key_change="/key-change",
    )
    return SimpleNamespace(
        server=SimpleNamespace(external_url=external_url),
        api=SimpleNamespace(base_path=base_path),
        acme=SimpleNamespace(paths=paths),
        ari=SimpleNamespace(enabled=ari_enabled, path=ari_path),
    )


# ---------------------------------------------------------------------------
# TestAcmeUrls
# ---------------------------------------------------------------------------


class TestAcmeUrls:
    def test_directory(self):
        urls = AcmeUrls(_make_settings())
        assert urls.directory == "https://acme.example.com/acme/directory"

    def test_new_nonce(self):
        urls = AcmeUrls(_make_settings())
        assert urls.new_nonce == "https://acme.example.com/acme/new-nonce"

    def test_new_account(self):
        urls = AcmeUrls(_make_settings())
        assert urls.new_account == "https://acme.example.com/acme/new-acct"

    def test_new_order(self):
        urls = AcmeUrls(_make_settings())
        assert urls.new_order == "https://acme.example.com/acme/new-order"

    def test_new_authz(self):
        urls = AcmeUrls(_make_settings())
        assert urls.new_authz == "https://acme.example.com/acme/new-authz"

    def test_revoke_cert(self):
        urls = AcmeUrls(_make_settings())
        assert urls.revoke_cert == "https://acme.example.com/acme/revoke-cert"

    def test_key_change(self):
        urls = AcmeUrls(_make_settings())
        assert urls.key_change == "https://acme.example.com/acme/key-change"

    def test_account_url(self):
        urls = AcmeUrls(_make_settings())
        uid = UUID("12345678-1234-5678-1234-567812345678")
        assert urls.account_url(uid) == f"https://acme.example.com/acme/acct/{uid}"

    def test_order_url(self):
        urls = AcmeUrls(_make_settings())
        uid = UUID("12345678-1234-5678-1234-567812345678")
        assert urls.order_url(uid) == f"https://acme.example.com/acme/order/{uid}"

    def test_finalize_url(self):
        urls = AcmeUrls(_make_settings())
        uid = UUID("12345678-1234-5678-1234-567812345678")
        assert urls.finalize_url(uid) == f"https://acme.example.com/acme/order/{uid}/finalize"

    def test_authorization_url(self):
        urls = AcmeUrls(_make_settings())
        uid = UUID("12345678-1234-5678-1234-567812345678")
        assert urls.authorization_url(uid) == f"https://acme.example.com/acme/authz/{uid}"

    def test_challenge_url(self):
        urls = AcmeUrls(_make_settings())
        uid = UUID("12345678-1234-5678-1234-567812345678")
        assert urls.challenge_url(uid) == f"https://acme.example.com/acme/chall/{uid}"

    def test_certificate_url(self):
        urls = AcmeUrls(_make_settings())
        uid = UUID("12345678-1234-5678-1234-567812345678")
        assert urls.certificate_url(uid) == f"https://acme.example.com/acme/cert/{uid}"

    def test_orders_url(self):
        urls = AcmeUrls(_make_settings())
        uid = UUID("12345678-1234-5678-1234-567812345678")
        assert urls.orders_url(uid) == f"https://acme.example.com/acme/acct/{uid}/orders"

    def test_renewal_info_disabled(self):
        urls = AcmeUrls(_make_settings(ari_enabled=False))
        assert urls.renewal_info == ""

    def test_renewal_info_enabled(self):
        urls = AcmeUrls(_make_settings(ari_enabled=True, ari_path="/renewalInfo"))
        assert urls.renewal_info == "https://acme.example.com/acme/renewalInfo"

    def test_base_path_trailing_slash_stripped(self):
        urls = AcmeUrls(_make_settings(base_path="/acme/"))
        assert urls.directory == "https://acme.example.com/acme/directory"
