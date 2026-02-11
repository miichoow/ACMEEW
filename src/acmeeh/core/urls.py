"""Centralized URL builder for ACME resources.

Pre-computes the root prefix from settings and provides typed methods
for all resource URLs referenced in RFC 8555 responses.

Usage::

    from acmeeh.core.urls import AcmeUrls

    urls = AcmeUrls(settings)
    urls.directory          # "https://acme.example.com/directory"
    urls.order_url(order_id)  # "https://acme.example.com/order/<id>"
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from acmeeh.config.settings import AcmeehSettings


class AcmeUrls:
    """Build absolute URLs for all ACME resources.

    Parameters
    ----------
    settings:
        The fully-typed :class:`AcmeehSettings` tree.

    """

    def __init__(self, settings: AcmeehSettings) -> None:
        """Initialize URL builder from application settings."""
        base_path = settings.api.base_path.rstrip("/")
        self._root = settings.server.external_url + base_path
        self._paths = settings.acme.paths
        self._ari_path = settings.ari.path if settings.ari.enabled else None

    # -- Directory resource URLs (static) ------------------------------------

    @property
    def directory(self) -> str:
        """Return the directory endpoint URL."""
        return self._root + self._paths.directory

    @property
    def new_nonce(self) -> str:
        """Return the new-nonce endpoint URL."""
        return self._root + self._paths.new_nonce

    @property
    def new_account(self) -> str:
        """Return the new-account endpoint URL."""
        return self._root + self._paths.new_account

    @property
    def new_order(self) -> str:
        """Return the new-order endpoint URL."""
        return self._root + self._paths.new_order

    @property
    def new_authz(self) -> str:
        """Return the new-authz endpoint URL."""
        return self._root + self._paths.new_authz

    @property
    def revoke_cert(self) -> str:
        """Return the revoke-cert endpoint URL."""
        return self._root + self._paths.revoke_cert

    @property
    def key_change(self) -> str:
        """Return the key-change endpoint URL."""
        return self._root + self._paths.key_change

    @property
    def renewal_info(self) -> str:
        """Return the ARI renewal-info endpoint URL, or empty string."""
        if self._ari_path:
            return self._root + self._ari_path
        return ""

    # -- Per-resource URLs (dynamic) -----------------------------------------

    def account_url(self, account_id: UUID) -> str:
        """Return the URL for a specific account."""
        return f"{self._root}/acct/{account_id}"

    def order_url(self, order_id: UUID) -> str:
        """Return the URL for a specific order."""
        return f"{self._root}/order/{order_id}"

    def finalize_url(self, order_id: UUID) -> str:
        """Return the finalize URL for a specific order."""
        return f"{self._root}/order/{order_id}/finalize"

    def authorization_url(self, authz_id: UUID) -> str:
        """Return the URL for a specific authorization."""
        return f"{self._root}/authz/{authz_id}"

    def challenge_url(self, challenge_id: UUID) -> str:
        """Return the URL for a specific challenge."""
        return f"{self._root}/chall/{challenge_id}"

    def certificate_url(self, cert_id: UUID) -> str:
        """Return the URL for a specific certificate."""
        return f"{self._root}/cert/{cert_id}"

    def orders_url(self, account_id: UUID) -> str:
        """Return the orders-list URL for a specific account."""
        return f"{self._root}/acct/{account_id}/orders"
