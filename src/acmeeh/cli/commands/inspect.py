"""Inspect subcommand — query ACME resources for debugging.

Usage::

    acmeeh -c config.yaml inspect order <uuid>
    acmeeh -c config.yaml inspect certificate <uuid-or-serial>
    acmeeh -c config.yaml inspect account <uuid>
"""

from __future__ import annotations

import sys
from uuid import UUID


def run_inspect(config, args) -> None:
    """Dispatch to the appropriate inspect sub-handler."""
    sub = getattr(args, "inspect_command", None)
    if sub is None:
        sys.exit(1)

    from acmeeh.db import init_database

    db = init_database(config.settings.database)

    if sub == "order":
        _inspect_order(db, args.resource_id)
    elif sub == "certificate":
        _inspect_certificate(db, args.resource_id)
    elif sub == "account":
        _inspect_account(db, args.resource_id)
    else:
        sys.exit(1)


def _inspect_order(db, resource_id: str) -> None:
    """Print order details with linked authorizations and challenges."""
    from acmeeh.repositories.authorization import AuthorizationRepository
    from acmeeh.repositories.challenge import ChallengeRepository
    from acmeeh.repositories.order import OrderRepository

    order_repo = OrderRepository(db)
    authz_repo = AuthorizationRepository(db)
    challenge_repo = ChallengeRepository(db)

    try:
        oid = UUID(resource_id)
    except ValueError:
        sys.exit(1)

    order = order_repo.find_by_id(oid)
    if order is None:
        sys.exit(1)

    result = {
        "id": str(order.id),
        "account_id": str(order.account_id),
        "status": order.status.value,
        "identifiers": [{"type": i.type.value, "value": i.value} for i in order.identifiers],
        "expires": str(order.expires) if order.expires else None,
        "created_at": str(order.created_at) if order.created_at else None,
        "certificate_id": str(order.certificate_id) if order.certificate_id else None,
        "error": order.error,
    }

    authz_ids = order_repo.find_authorization_ids(oid)
    authzs = []
    for aid in authz_ids:
        authz = authz_repo.find_by_id(aid)
        if authz is None:
            continue
        challenges = challenge_repo.find_by_authorization(aid)
        authzs.append(
            {
                "id": str(authz.id),
                "identifier": f"{authz.identifier_type.value}:{authz.identifier_value}",
                "status": authz.status.value,
                "wildcard": authz.wildcard,
                "expires": str(authz.expires) if authz.expires else None,
                "challenges": [
                    {
                        "id": str(c.id),
                        "type": c.type.value,
                        "status": c.status.value,
                        "token": c.token[:16] + "...",
                        "retry_count": c.retry_count,
                        "error": c.error,
                    }
                    for c in challenges
                ],
            }
        )

    result["authorizations"] = authzs


def _inspect_certificate(db, resource_id: str) -> None:
    """Print certificate details."""
    from acmeeh.repositories.certificate import CertificateRepository

    cert_repo = CertificateRepository(db)

    # Try UUID first, then serial number
    cert = None
    try:
        cid = UUID(resource_id)
        cert = cert_repo.find_by_id(cid)
    except ValueError:
        pass

    if cert is None:
        cert = cert_repo.find_by_serial(resource_id)

    if cert is None:
        sys.exit(1)

    {
        "id": str(cert.id),
        "account_id": str(cert.account_id),
        "order_id": str(cert.order_id) if cert.order_id else None,
        "serial_number": cert.serial_number,
        "fingerprint": cert.fingerprint,
        "not_before": str(cert.not_before_cert) if cert.not_before_cert else None,
        "not_after": str(cert.not_after_cert) if cert.not_after_cert else None,
        "revoked_at": str(cert.revoked_at) if cert.revoked_at else None,
        "revocation_reason": cert.revocation_reason.name if cert.revocation_reason else None,
        "san_values": cert.san_values,
        "public_key_fingerprint": cert.public_key_fingerprint,
        "created_at": str(cert.created_at) if cert.created_at else None,
    }


def _inspect_account(db, resource_id: str) -> None:
    """Print account details with contacts and order count."""
    from acmeeh.repositories import AccountContactRepository, OrderRepository
    from acmeeh.repositories.account import AccountRepository

    account_repo = AccountRepository(db)
    contact_repo = AccountContactRepository(db)
    order_repo = OrderRepository(db)

    try:
        aid = UUID(resource_id)
    except ValueError:
        sys.exit(1)

    account = account_repo.find_by_id(aid)
    if account is None:
        sys.exit(1)

    contacts = contact_repo.find_by_account(aid)
    orders = order_repo.find_by_account(aid)

    result = {
        "id": str(account.id),
        "status": account.status.value,
        "tos_agreed": account.tos_agreed,
        "contacts": [c.contact_uri for c in contacts],
        "order_count": len(orders),
        "orders_by_status": {},
        "created_at": str(account.created_at) if account.created_at else None,
    }

    for o in orders:
        status = o.status.value
        result["orders_by_status"][status] = result["orders_by_status"].get(status, 0) + 1
