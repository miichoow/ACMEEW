"""Abstract base class for ACMEEH lifecycle hooks.

All custom hooks must inherit from :class:`Hook` and override the
event methods they are interested in.  Unimplemented methods are
no-ops by default.

Usage::

    from acmeeh.hooks import Hook

    class MyAuditHook(Hook):
        def on_certificate_issuance(self, ctx: dict) -> None:
            send_to_siem(ctx)
"""

from __future__ import annotations

import abc


class Hook(abc.ABC):
    """Base class for all ACMEEH lifecycle hooks.

    Parameters
    ----------
    config:
        Optional passthrough configuration from the hook entry's
        ``config`` dict in the ACMEEH config file.

    """

    def __init__(self, config: dict | None = None) -> None:
        self.config = config or {}

    @classmethod
    def validate_config(cls, config: dict) -> None:
        """Validate hook-specific configuration at load time.

        Override in subclasses to reject invalid config before the
        hook is instantiated.  Raise :class:`ValueError` if *config*
        is not acceptable.

        The default implementation is a no-op.
        """

    # -- Account events ---------------------------------------------------

    def on_account_registration(self, ctx: dict) -> None:
        """Called after a new account is created.

        Context keys: ``account_id``, ``contacts``,
        ``jwk_thumbprint``, ``tos_agreed``.
        """

    # -- Order events -----------------------------------------------------

    def on_order_creation(self, ctx: dict) -> None:
        """Called after a new order is created.

        Context keys: ``order_id``, ``account_id``,
        ``identifiers``, ``authz_ids``.
        """

    # -- Challenge events -------------------------------------------------

    def on_challenge_before_validate(self, ctx: dict) -> None:
        """Called before a challenge validation attempt.

        Context keys: ``challenge_type``, ``token``,
        ``identifier_type``, ``identifier_value``.
        """

    def on_challenge_after_validate(self, ctx: dict) -> None:
        """Called after a successful challenge validation.

        Context keys: ``challenge_type``, ``token``,
        ``identifier_type``, ``identifier_value``, ``result``.
        """

    def on_challenge_failure(self, ctx: dict) -> None:
        """Called when a challenge validation fails terminally.

        Context keys: ``challenge_type``, ``token``,
        ``identifier_type``, ``identifier_value``, ``error``.
        """

    def on_challenge_retry(self, ctx: dict) -> None:
        """Called when a challenge validation fails but will be retried.

        Context keys: ``challenge_type``, ``token``,
        ``identifier_type``, ``identifier_value``, ``error``,
        ``retry_count``.
        """

    # -- Certificate events -----------------------------------------------

    def on_certificate_issuance(self, ctx: dict) -> None:
        """Called after a certificate is issued.

        Context keys: ``certificate_id``, ``order_id``,
        ``account_id``, ``serial_number``, ``domains``, ``not_after``.
        """

    def on_certificate_revocation(self, ctx: dict) -> None:
        """Called after a certificate is revoked.

        Context keys: ``certificate_id``, ``account_id``,
        ``serial_number``, ``reason``.
        """

    def on_certificate_delivery(self, ctx: dict) -> None:
        """Called when a certificate is downloaded.

        Context keys: ``certificate_id``, ``account_id``,
        ``serial_number``.
        """

    # -- CT events --------------------------------------------------------

    def on_ct_submission(self, ctx: dict) -> None:
        """Called after a certificate is submitted to CT logs.

        Context keys: ``certificate_id``, ``serial_number``,
        ``ct_log_url``, ``sct``.
        """
