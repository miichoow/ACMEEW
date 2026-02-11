"""Unit tests for acmeeh.core.types — Enumerated types."""

from __future__ import annotations

import json

import pytest

from acmeeh.core.types import (
    AccountStatus,
    AdminRole,
    AuthorizationStatus,
    ChallengeStatus,
    ChallengeType,
    IdentifierType,
    NotificationStatus,
    OrderStatus,
    RevocationReason,
)

# ---------------------------------------------------------------------------
# TestStringEnums
# ---------------------------------------------------------------------------


class TestStringEnums:
    @pytest.mark.parametrize(
        "enum_cls,member,expected",
        [
            (AccountStatus, "VALID", "valid"),
            (AccountStatus, "DEACTIVATED", "deactivated"),
            (AccountStatus, "REVOKED", "revoked"),
            (OrderStatus, "PENDING", "pending"),
            (OrderStatus, "READY", "ready"),
            (OrderStatus, "PROCESSING", "processing"),
            (OrderStatus, "VALID", "valid"),
            (OrderStatus, "INVALID", "invalid"),
            (AuthorizationStatus, "PENDING", "pending"),
            (AuthorizationStatus, "EXPIRED", "expired"),
            (ChallengeStatus, "PENDING", "pending"),
            (ChallengeStatus, "PROCESSING", "processing"),
            (IdentifierType, "DNS", "dns"),
            (IdentifierType, "IP", "ip"),
            (NotificationStatus, "PENDING", "pending"),
            (NotificationStatus, "SENT", "sent"),
            (AdminRole, "ADMIN", "admin"),
        ],
    )
    def test_string_value(self, enum_cls, member, expected):
        assert enum_cls[member].value == expected
        assert enum_cls[member] == expected  # str enum comparison

    def test_json_round_trip(self):
        data = {"status": AccountStatus.VALID}
        serialized = json.dumps(data)
        assert '"valid"' in serialized
        deserialized = json.loads(serialized)
        assert deserialized["status"] == "valid"
        assert AccountStatus(deserialized["status"]) == AccountStatus.VALID

    def test_membership_check(self):
        assert "valid" in [s.value for s in AccountStatus]
        assert "invalid" not in [s.value for s in AccountStatus]


# ---------------------------------------------------------------------------
# TestRevocationReason
# ---------------------------------------------------------------------------


class TestRevocationReason:
    @pytest.mark.parametrize(
        "member,code",
        [
            ("UNSPECIFIED", 0),
            ("KEY_COMPROMISE", 1),
            ("CA_COMPROMISE", 2),
            ("AFFILIATION_CHANGED", 3),
            ("SUPERSEDED", 4),
            ("CESSATION_OF_OPERATION", 5),
            ("CERTIFICATE_HOLD", 6),
            ("REMOVE_FROM_CRL", 8),
            ("PRIVILEGE_WITHDRAWN", 9),
            ("AA_COMPROMISE", 10),
        ],
    )
    def test_rfc5280_codes(self, member, code):
        assert RevocationReason[member].value == code
        assert int(RevocationReason[member]) == code

    def test_gap_at_7(self):
        """RFC 5280 code 7 is unused."""
        values = {r.value for r in RevocationReason}
        assert 7 not in values

    def test_int_conversion(self):
        assert int(RevocationReason.KEY_COMPROMISE) == 1


# ---------------------------------------------------------------------------
# TestChallengeType
# ---------------------------------------------------------------------------


class TestChallengeType:
    @pytest.mark.parametrize(
        "member,wire_value",
        [
            ("HTTP_01", "http-01"),
            ("DNS_01", "dns-01"),
            ("TLS_ALPN_01", "tls-alpn-01"),
        ],
    )
    def test_wire_format(self, member, wire_value):
        assert ChallengeType[member].value == wire_value
