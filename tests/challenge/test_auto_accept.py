"""Tests for auto-accept challenge validators."""

from __future__ import annotations

from acmeeh.challenge.auto_accept import (
    AutoAcceptDnsValidator,
    AutoAcceptHttpValidator,
    AutoAcceptTlsValidator,
)
from acmeeh.core.types import ChallengeType


class TestAutoAcceptHttpValidator:
    def test_challenge_type(self):
        v = AutoAcceptHttpValidator()
        assert v.challenge_type == ChallengeType.HTTP_01

    def test_auto_validate_is_true(self):
        v = AutoAcceptHttpValidator()
        assert v.auto_validate is True

    def test_max_retries_is_zero(self):
        v = AutoAcceptHttpValidator()
        assert v.max_retries == 0

    def test_supports_dns_and_ip(self):
        v = AutoAcceptHttpValidator()
        assert v.supports_identifier("dns")
        assert v.supports_identifier("ip")

    def test_validate_succeeds(self):
        v = AutoAcceptHttpValidator()
        # Should not raise
        v.validate(
            token="test-token",
            jwk={"kty": "EC"},
            identifier_type="dns",
            identifier_value="example.com",
        )

    def test_validate_succeeds_with_ip(self):
        v = AutoAcceptHttpValidator()
        v.validate(
            token="test-token",
            jwk={"kty": "EC"},
            identifier_type="ip",
            identifier_value="192.168.1.1",
        )


class TestAutoAcceptDnsValidator:
    def test_challenge_type(self):
        v = AutoAcceptDnsValidator()
        assert v.challenge_type == ChallengeType.DNS_01

    def test_auto_validate_is_true(self):
        v = AutoAcceptDnsValidator()
        assert v.auto_validate is True

    def test_max_retries_is_zero(self):
        v = AutoAcceptDnsValidator()
        assert v.max_retries == 0

    def test_supports_dns_and_ip(self):
        v = AutoAcceptDnsValidator()
        assert v.supports_identifier("dns")
        assert v.supports_identifier("ip")

    def test_validate_succeeds(self):
        v = AutoAcceptDnsValidator()
        v.validate(
            token="test-token",
            jwk={"kty": "EC"},
            identifier_type="dns",
            identifier_value="example.com",
        )


class TestAutoAcceptTlsValidator:
    def test_challenge_type(self):
        v = AutoAcceptTlsValidator()
        assert v.challenge_type == ChallengeType.TLS_ALPN_01

    def test_auto_validate_is_true(self):
        v = AutoAcceptTlsValidator()
        assert v.auto_validate is True

    def test_max_retries_is_zero(self):
        v = AutoAcceptTlsValidator()
        assert v.max_retries == 0

    def test_supports_dns_and_ip(self):
        v = AutoAcceptTlsValidator()
        assert v.supports_identifier("dns")
        assert v.supports_identifier("ip")

    def test_validate_succeeds(self):
        v = AutoAcceptTlsValidator()
        v.validate(
            token="test-token",
            jwk={"kty": "EC"},
            identifier_type="dns",
            identifier_value="example.com",
        )
