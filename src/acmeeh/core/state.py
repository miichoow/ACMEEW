"""ACME resource state machines (RFC 8555).

Defines the valid status transitions for orders, authorizations,
and challenges.  All transitions are enforced via :func:`assert_transition`.

Usage::

    from acmeeh.core.state import assert_transition
    from acmeeh.core.types import OrderStatus

    assert_transition(
        OrderStatus.PENDING, OrderStatus.READY,
        ORDER_TRANSITIONS,
    )
"""

from __future__ import annotations

import logging

from acmeeh.core.types import (
    AuthorizationStatus,
    ChallengeStatus,
    OrderStatus,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Order: pending → ready/invalid, ready → processing/invalid,
#         processing → valid/invalid.  valid & invalid are terminal.
# ---------------------------------------------------------------------------

ORDER_TRANSITIONS: dict[OrderStatus, frozenset[OrderStatus]] = {
    OrderStatus.PENDING: frozenset({OrderStatus.READY, OrderStatus.INVALID}),
    OrderStatus.READY: frozenset({OrderStatus.PROCESSING, OrderStatus.INVALID}),
    OrderStatus.PROCESSING: frozenset({OrderStatus.VALID, OrderStatus.INVALID}),
    OrderStatus.VALID: frozenset(),
    OrderStatus.INVALID: frozenset(),
}

# ---------------------------------------------------------------------------
# Authorization: pending → valid/invalid/deactivated/expired,
#                valid → deactivated/revoked.  Others are terminal.
# ---------------------------------------------------------------------------

AUTHORIZATION_TRANSITIONS: dict[AuthorizationStatus, frozenset[AuthorizationStatus]] = {
    AuthorizationStatus.PENDING: frozenset(
        {
            AuthorizationStatus.VALID,
            AuthorizationStatus.INVALID,
            AuthorizationStatus.DEACTIVATED,
            AuthorizationStatus.EXPIRED,
        }
    ),
    AuthorizationStatus.VALID: frozenset(
        {
            AuthorizationStatus.DEACTIVATED,
            AuthorizationStatus.REVOKED,
        }
    ),
    AuthorizationStatus.INVALID: frozenset(),
    AuthorizationStatus.DEACTIVATED: frozenset(),
    AuthorizationStatus.EXPIRED: frozenset(),
    AuthorizationStatus.REVOKED: frozenset(),
}

# ---------------------------------------------------------------------------
# Challenge: pending → processing, processing → valid/invalid/pending (retry)
# ---------------------------------------------------------------------------

CHALLENGE_TRANSITIONS: dict[ChallengeStatus, frozenset[ChallengeStatus]] = {
    ChallengeStatus.PENDING: frozenset({ChallengeStatus.PROCESSING}),
    ChallengeStatus.PROCESSING: frozenset(
        {
            ChallengeStatus.VALID,
            ChallengeStatus.INVALID,
            ChallengeStatus.PENDING,  # retry
        }
    ),
    ChallengeStatus.VALID: frozenset(),
    ChallengeStatus.INVALID: frozenset(),
}


_RESOURCE_TYPE_NAMES = {
    id(ORDER_TRANSITIONS): "order",
    id(AUTHORIZATION_TRANSITIONS): "authorization",
    id(CHALLENGE_TRANSITIONS): "challenge",
}


def assert_transition(
    current: OrderStatus | AuthorizationStatus | ChallengeStatus,
    target: OrderStatus | AuthorizationStatus | ChallengeStatus,
    table: dict,
) -> None:
    """Raise :class:`ValueError` if *current* → *target* is not allowed.

    Parameters
    ----------
    current:
        The current status of the resource.
    target:
        The desired new status.
    table:
        One of :data:`ORDER_TRANSITIONS`, :data:`AUTHORIZATION_TRANSITIONS`,
        or :data:`CHALLENGE_TRANSITIONS`.

    """
    allowed = table.get(current)
    if allowed is None:
        msg = f"Unknown status {current!r}"
        raise ValueError(msg)
    if target not in allowed:
        msg = (
            f"Invalid transition {current.value!r} -> {target.value!r}; "
            f"allowed targets: {sorted(s.value for s in allowed) or '(terminal)'}"
        )
        raise ValueError(
            msg,
        )


def log_transition(
    resource_type: str,
    resource_id,
    from_status,
    to_status,
    *,
    reason: str | None = None,
) -> None:
    """Emit a structured log entry for a state transition.

    Parameters
    ----------
    resource_type:
        ``"order"``, ``"authorization"``, or ``"challenge"``.
    resource_id:
        The UUID of the resource.
    from_status:
        The previous status value.
    to_status:
        The new status value.
    reason:
        Optional human-readable reason for the transition.

    """
    extra = {
        "event": "state_transition",
        "resource_type": resource_type,
        "resource_id": str(resource_id),
        "from_status": from_status.value if hasattr(from_status, "value") else str(from_status),
        "to_status": to_status.value if hasattr(to_status, "value") else str(to_status),
    }
    if reason:
        extra["reason"] = reason
    log.info(
        "%s %s: %s -> %s%s",
        resource_type,
        resource_id,
        extra["from_status"],
        extra["to_status"],
        f" ({reason})" if reason else "",
        extra=extra,
    )
