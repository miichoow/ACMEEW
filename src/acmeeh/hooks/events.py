"""Canonical hook event definitions.

Single source of truth for all known lifecycle event names and their
corresponding :class:`~acmeeh.hooks.base.Hook` method names.

This module has **zero** internal dependencies — it can be imported
from anywhere without circular import risk.
"""

from __future__ import annotations

EVENT_METHOD_MAP: dict[str, str] = {
    "account.registration": "on_account_registration",
    "order.creation": "on_order_creation",
    "challenge.before_validate": "on_challenge_before_validate",
    "challenge.after_validate": "on_challenge_after_validate",
    "challenge.on_failure": "on_challenge_failure",
    "challenge.on_retry": "on_challenge_retry",
    "certificate.issuance": "on_certificate_issuance",
    "certificate.revocation": "on_certificate_revocation",
    "certificate.delivery": "on_certificate_delivery",
    "ct.submission": "on_ct_submission",
}

KNOWN_EVENTS: frozenset[str] = frozenset(EVENT_METHOD_MAP.keys())
