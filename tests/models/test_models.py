"""Unit tests for acmeeh.models — Frozen dataclass models."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from acmeeh.core.types import (
    AccountStatus,
    AuthorizationStatus,
    ChallengeStatus,
    ChallengeType,
    IdentifierType,
    NotificationStatus,
    NotificationType,
    OrderStatus,
)
from acmeeh.models.account import _EPOCH, Account, AccountContact
from acmeeh.models.authorization import Authorization
from acmeeh.models.certificate import Certificate
from acmeeh.models.challenge import Challenge
from acmeeh.models.nonce import Nonce
from acmeeh.models.notification import Notification
from acmeeh.models.order import Identifier, Order

# ---------------------------------------------------------------------------
# TestAccount
# ---------------------------------------------------------------------------


class TestAccount:
    def test_construction(self):
        uid = uuid4()
        a = Account(
            id=uid,
            jwk_thumbprint="tp123",
            jwk={"kty": "EC"},
            status=AccountStatus.VALID,
        )
        assert a.id == uid
        assert a.jwk_thumbprint == "tp123"
        assert a.status == AccountStatus.VALID

    def test_frozen(self):
        a = Account(
            id=uuid4(),
            jwk_thumbprint="tp",
            jwk={},
            status=AccountStatus.VALID,
        )
        with pytest.raises(AttributeError):
            a.status = AccountStatus.DEACTIVATED

    def test_defaults(self):
        a = Account(
            id=uuid4(),
            jwk_thumbprint="tp",
            jwk={},
            status=AccountStatus.VALID,
        )
        assert a.tos_agreed is False
        assert a.created_at == _EPOCH
        assert a.updated_at == _EPOCH


# ---------------------------------------------------------------------------
# TestAccountContact
# ---------------------------------------------------------------------------


class TestAccountContact:
    def test_construction(self):
        uid = uuid4()
        aid = uuid4()
        c = AccountContact(id=uid, account_id=aid, contact_uri="mailto:a@b.com")
        assert c.id == uid
        assert c.account_id == aid
        assert c.contact_uri == "mailto:a@b.com"

    def test_frozen(self):
        c = AccountContact(id=uuid4(), account_id=uuid4(), contact_uri="mailto:a@b.com")
        with pytest.raises(AttributeError):
            c.contact_uri = "mailto:other@example.com"


# ---------------------------------------------------------------------------
# TestOrder
# ---------------------------------------------------------------------------


class TestOrder:
    def test_construction(self):
        uid = uuid4()
        aid = uuid4()
        idents = (Identifier(type=IdentifierType.DNS, value="example.com"),)
        o = Order(
            id=uid,
            account_id=aid,
            status=OrderStatus.PENDING,
            identifiers=idents,
            identifiers_hash="abc123",
        )
        assert o.id == uid
        assert o.identifiers == idents
        assert o.status == OrderStatus.PENDING

    def test_frozen(self):
        o = Order(
            id=uuid4(),
            account_id=uuid4(),
            status=OrderStatus.PENDING,
            identifiers=(),
            identifiers_hash="x",
        )
        with pytest.raises(AttributeError):
            o.status = OrderStatus.READY

    def test_defaults(self):
        o = Order(
            id=uuid4(),
            account_id=uuid4(),
            status=OrderStatus.PENDING,
            identifiers=(),
            identifiers_hash="x",
        )
        assert o.expires is None
        assert o.error is None
        assert o.certificate_id is None
        assert o.not_before is None
        assert o.not_after is None
        assert o.replaces is None


# ---------------------------------------------------------------------------
# TestIdentifier
# ---------------------------------------------------------------------------


class TestIdentifier:
    def test_construction(self):
        i = Identifier(type=IdentifierType.DNS, value="example.com")
        assert i.type == IdentifierType.DNS
        assert i.value == "example.com"

    def test_frozen(self):
        i = Identifier(type=IdentifierType.DNS, value="example.com")
        with pytest.raises(AttributeError):
            i.value = "other.com"

    def test_equality(self):
        a = Identifier(type=IdentifierType.DNS, value="example.com")
        b = Identifier(type=IdentifierType.DNS, value="example.com")
        assert a == b

    def test_inequality(self):
        a = Identifier(type=IdentifierType.DNS, value="example.com")
        b = Identifier(type=IdentifierType.IP, value="example.com")
        assert a != b


# ---------------------------------------------------------------------------
# TestAuthorization
# ---------------------------------------------------------------------------


class TestAuthorization:
    def test_construction(self):
        uid = uuid4()
        a = Authorization(
            id=uid,
            account_id=uuid4(),
            identifier_type=IdentifierType.DNS,
            identifier_value="example.com",
            status=AuthorizationStatus.PENDING,
        )
        assert a.id == uid
        assert a.identifier_type == IdentifierType.DNS

    def test_frozen(self):
        a = Authorization(
            id=uuid4(),
            account_id=uuid4(),
            identifier_type=IdentifierType.DNS,
            identifier_value="example.com",
            status=AuthorizationStatus.PENDING,
        )
        with pytest.raises(AttributeError):
            a.status = AuthorizationStatus.VALID

    def test_wildcard_default(self):
        a = Authorization(
            id=uuid4(),
            account_id=uuid4(),
            identifier_type=IdentifierType.DNS,
            identifier_value="example.com",
            status=AuthorizationStatus.PENDING,
        )
        assert a.wildcard is False


# ---------------------------------------------------------------------------
# TestChallenge
# ---------------------------------------------------------------------------


class TestChallenge:
    def test_construction(self):
        uid = uuid4()
        c = Challenge(
            id=uid,
            authorization_id=uuid4(),
            type=ChallengeType.HTTP_01,
            token="tokenvalue",
            status=ChallengeStatus.PENDING,
        )
        assert c.id == uid
        assert c.type == ChallengeType.HTTP_01

    def test_frozen(self):
        c = Challenge(
            id=uuid4(),
            authorization_id=uuid4(),
            type=ChallengeType.DNS_01,
            token="t",
            status=ChallengeStatus.PENDING,
        )
        with pytest.raises(AttributeError):
            c.status = ChallengeStatus.VALID

    def test_retry_count_default(self):
        c = Challenge(
            id=uuid4(),
            authorization_id=uuid4(),
            type=ChallengeType.HTTP_01,
            token="t",
            status=ChallengeStatus.PENDING,
        )
        assert c.retry_count == 0
        assert c.error is None
        assert c.validated_at is None


# ---------------------------------------------------------------------------
# TestCertificate
# ---------------------------------------------------------------------------


class TestCertificate:
    def test_construction(self):
        uid = uuid4()
        now = datetime.now(UTC)
        c = Certificate(
            id=uid,
            account_id=uuid4(),
            order_id=uuid4(),
            serial_number="AABB",
            fingerprint="sha256:abc",
            pem_chain="-----BEGIN CERTIFICATE-----",
            not_before_cert=now,
            not_after_cert=now,
        )
        assert c.serial_number == "AABB"

    def test_frozen(self):
        now = datetime.now(UTC)
        c = Certificate(
            id=uuid4(),
            account_id=uuid4(),
            order_id=uuid4(),
            serial_number="AA",
            fingerprint="fp",
            pem_chain="pem",
            not_before_cert=now,
            not_after_cert=now,
        )
        with pytest.raises(AttributeError):
            c.serial_number = "BB"

    def test_revocation_fields_optional(self):
        now = datetime.now(UTC)
        c = Certificate(
            id=uuid4(),
            account_id=uuid4(),
            order_id=uuid4(),
            serial_number="AA",
            fingerprint="fp",
            pem_chain="pem",
            not_before_cert=now,
            not_after_cert=now,
        )
        assert c.revoked_at is None
        assert c.revocation_reason is None


# ---------------------------------------------------------------------------
# TestNonce
# ---------------------------------------------------------------------------


class TestNonce:
    def test_construction(self):
        exp = datetime.now(UTC)
        n = Nonce(nonce="abc123", expires_at=exp)
        assert n.nonce == "abc123"
        assert n.expires_at == exp

    def test_frozen(self):
        n = Nonce(nonce="abc", expires_at=datetime.now(UTC))
        with pytest.raises(AttributeError):
            n.nonce = "xyz"


# ---------------------------------------------------------------------------
# TestNotification
# ---------------------------------------------------------------------------


class TestNotification:
    def test_construction(self):
        uid = uuid4()
        n = Notification(
            id=uid,
            notification_type=NotificationType.DELIVERY_SUCCEEDED,
            recipient="admin@example.com",
            subject="Cert issued",
            body="Your cert is ready",
        )
        assert n.id == uid
        assert n.notification_type == NotificationType.DELIVERY_SUCCEEDED

    def test_frozen(self):
        n = Notification(
            id=uuid4(),
            notification_type=NotificationType.DELIVERY_SUCCEEDED,
            recipient="a@b.com",
            subject="s",
            body="b",
        )
        with pytest.raises(AttributeError):
            n.subject = "new"

    def test_status_default(self):
        n = Notification(
            id=uuid4(),
            notification_type=NotificationType.DELIVERY_SUCCEEDED,
            recipient="a@b.com",
            subject="s",
            body="b",
        )
        assert n.status == NotificationStatus.PENDING
        assert n.retry_count == 0
        assert n.account_id is None
