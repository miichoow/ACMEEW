"""Additional DNS-01 challenge validator tests for improved coverage."""

from __future__ import annotations

import base64
import hashlib
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from acmeeh.challenge.base import ChallengeError
from acmeeh.challenge.dns01 import Dns01Validator
from acmeeh.core.types import ChallengeType

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

KEY_AUTHZ = "test-token.mock-thumbprint"
EXPECTED_DIGEST = (
    base64.urlsafe_b64encode(
        hashlib.sha256(KEY_AUTHZ.encode("ascii")).digest(),
    )
    .rstrip(b"=")
    .decode("ascii")
)


def _make_txt_rdata(value: str) -> MagicMock:
    """Create a mock TXT rdata object with .strings attribute."""
    rdata = MagicMock()
    rdata.strings = (value.encode("ascii"),)
    return rdata


def _make_answer(txt_values: list[str], ad_flag: bool = False) -> MagicMock:
    """Create a mock dns.resolver.Answer with given TXT values."""
    answer = MagicMock()
    answer.__iter__ = lambda self: iter(
        [_make_txt_rdata(v) for v in txt_values],
    )

    # Mock the response for DNSSEC checks
    import dns.flags

    flags = dns.flags.AD if ad_flag else 0
    response = MagicMock()
    response.flags = flags
    answer.response = response

    return answer


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDns01Validator:
    """Tests for Dns01Validator.validate."""

    @pytest.fixture(autouse=True)
    def _patch_key_authorization(self):
        with patch(
            "acmeeh.challenge.dns01.key_authorization",
            return_value=KEY_AUTHZ,
        ):
            yield

    def test_wrong_identifier_type(self):
        """DNS-01 only supports 'dns' identifiers."""
        validator = Dns01Validator(settings=None)
        with pytest.raises(ChallengeError, match="only supports 'dns'") as exc_info:
            validator.validate(
                token="tok",
                jwk={"kty": "EC"},
                identifier_type="ip",
                identifier_value="192.0.2.1",
            )
        assert exc_info.value.retryable is False

    @patch("acmeeh.challenge.dns01.dns.resolver.Resolver")
    def test_successful_validation(self, mock_resolver_cls):
        """Matching TXT record -> success (no exception)."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        answer = _make_answer([EXPECTED_DIGEST])
        resolver.resolve.return_value = answer

        validator = Dns01Validator(settings=None)
        validator.validate(
            token="test-token",
            jwk={"kty": "EC"},
            identifier_type="dns",
            identifier_value="example.com",
        )

        resolver.resolve.assert_called_once_with(
            "_acme-challenge.example.com",
            "TXT",
        )

    @patch("acmeeh.challenge.dns01.dns.resolver.Resolver")
    def test_wildcard_domain_strips_prefix(self, mock_resolver_cls):
        """Wildcard identifier '*.example.com' strips the '*.' prefix."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        answer = _make_answer([EXPECTED_DIGEST])
        resolver.resolve.return_value = answer

        validator = Dns01Validator(settings=None)
        validator.validate(
            token="test-token",
            jwk={"kty": "EC"},
            identifier_type="dns",
            identifier_value="*.example.com",
        )

        resolver.resolve.assert_called_once_with(
            "_acme-challenge.example.com",
            "TXT",
        )

    @patch("acmeeh.challenge.dns01.dns.resolver.Resolver")
    def test_nxdomain_is_retryable(self, mock_resolver_cls):
        """NXDOMAIN -> ChallengeError(retryable=True)."""
        import dns.resolver

        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver
        resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

        validator = Dns01Validator(settings=None)
        with pytest.raises(ChallengeError, match="NXDOMAIN") as exc_info:
            validator.validate(
                token="test-token",
                jwk={"kty": "EC"},
                identifier_type="dns",
                identifier_value="example.com",
            )
        assert exc_info.value.retryable is True

    @patch("acmeeh.challenge.dns01.dns.resolver.Resolver")
    def test_noanswer_is_retryable(self, mock_resolver_cls):
        """NoAnswer -> ChallengeError(retryable=True)."""
        import dns.resolver

        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver
        resolver.resolve.side_effect = dns.resolver.NoAnswer()

        validator = Dns01Validator(settings=None)
        with pytest.raises(ChallengeError, match="no TXT records") as exc_info:
            validator.validate(
                token="test-token",
                jwk={"kty": "EC"},
                identifier_type="dns",
                identifier_value="example.com",
            )
        assert exc_info.value.retryable is True

    @patch("acmeeh.challenge.dns01.dns.resolver.Resolver")
    def test_nonameservers_is_retryable(self, mock_resolver_cls):
        """NoNameservers -> ChallengeError(retryable=True)."""
        import dns.resolver

        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver
        resolver.resolve.side_effect = dns.resolver.NoNameservers()

        validator = Dns01Validator(settings=None)
        with pytest.raises(ChallengeError, match="no nameservers") as exc_info:
            validator.validate(
                token="test-token",
                jwk={"kty": "EC"},
                identifier_type="dns",
                identifier_value="example.com",
            )
        assert exc_info.value.retryable is True

    @patch("acmeeh.challenge.dns01.dns.resolver.Resolver")
    def test_timeout_is_retryable(self, mock_resolver_cls):
        """Timeout -> ChallengeError(retryable=True)."""
        import dns.exception

        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver
        resolver.resolve.side_effect = dns.exception.Timeout()

        validator = Dns01Validator(settings=None)
        with pytest.raises(ChallengeError, match="timed out") as exc_info:
            validator.validate(
                token="test-token",
                jwk={"kty": "EC"},
                identifier_type="dns",
                identifier_value="example.com",
            )
        assert exc_info.value.retryable is True

    @patch("acmeeh.challenge.dns01.dns.resolver.Resolver")
    def test_generic_dns_exception_is_retryable(self, mock_resolver_cls):
        """Generic DNSException -> ChallengeError(retryable=True)."""
        import dns.exception

        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver
        resolver.resolve.side_effect = dns.exception.DNSException("generic error")

        validator = Dns01Validator(settings=None)
        with pytest.raises(ChallengeError, match="DNS error") as exc_info:
            validator.validate(
                token="test-token",
                jwk={"kty": "EC"},
                identifier_type="dns",
                identifier_value="example.com",
            )
        assert exc_info.value.retryable is True

    @patch("acmeeh.challenge.dns01.dns.resolver.Resolver")
    def test_txt_mismatch_is_retryable(self, mock_resolver_cls):
        """TXT record present but doesn't match -> ChallengeError(retryable=True)."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        answer = _make_answer(["wrong-value-here"])
        resolver.resolve.return_value = answer

        validator = Dns01Validator(settings=None)
        with pytest.raises(ChallengeError, match="no TXT record.*matches") as exc_info:
            validator.validate(
                token="test-token",
                jwk={"kty": "EC"},
                identifier_type="dns",
                identifier_value="example.com",
            )
        assert exc_info.value.retryable is True

    @patch("acmeeh.challenge.dns01.dns.resolver.Resolver")
    def test_dnssec_ad_flag_check_passes(self, mock_resolver_cls):
        """DNSSEC validation passes when AD flag is set."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        answer = _make_answer([EXPECTED_DIGEST], ad_flag=True)
        resolver.resolve.return_value = answer

        settings = SimpleNamespace(
            timeout_seconds=30,
            resolvers=(),
            require_dnssec=True,
            require_authoritative=False,
        )
        validator = Dns01Validator(settings=settings)
        # Should not raise
        validator.validate(
            token="test-token",
            jwk={"kty": "EC"},
            identifier_type="dns",
            identifier_value="example.com",
        )

    @patch("acmeeh.challenge.dns01.dns.resolver.Resolver")
    def test_dnssec_ad_flag_not_set_fails(self, mock_resolver_cls):
        """DNSSEC validation fails when AD flag is not set."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        answer = _make_answer([EXPECTED_DIGEST], ad_flag=False)
        resolver.resolve.return_value = answer

        settings = SimpleNamespace(
            timeout_seconds=30,
            resolvers=(),
            require_dnssec=True,
            require_authoritative=False,
        )
        validator = Dns01Validator(settings=settings)
        with pytest.raises(ChallengeError, match="AD flag not set") as exc_info:
            validator.validate(
                token="test-token",
                jwk={"kty": "EC"},
                identifier_type="dns",
                identifier_value="example.com",
            )
        assert exc_info.value.retryable is True

    @patch("acmeeh.challenge.dns01.dns.resolver.resolve")
    @patch("acmeeh.challenge.dns01.dns.resolver.zone_for_name")
    @patch("acmeeh.challenge.dns01.dns.resolver.Resolver")
    def test_authoritative_ns_resolution_fallback(
        self,
        mock_resolver_cls,
        mock_zone_for_name,
        mock_global_resolve,
    ):
        """Authoritative NS resolution finds NS IPs and uses them."""
        # Primary resolver (will be replaced by authoritative)
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        answer = _make_answer([EXPECTED_DIGEST])
        resolver.resolve.return_value = answer

        # zone_for_name returns a zone
        mock_zone = MagicMock()
        mock_zone_for_name.return_value = mock_zone

        # NS query returns one NS record
        ns_rdata = MagicMock()
        ns_rdata.target.to_text.return_value = "ns1.example.com."
        ns_answer = MagicMock()
        ns_answer.__iter__ = lambda self: iter([ns_rdata])

        # A record for NS
        a_rdata = MagicMock()
        a_rdata.address = "198.51.100.1"
        a_answer = MagicMock()
        a_answer.__iter__ = lambda self: iter([a_rdata])

        import dns.exception

        def resolve_side_effect(name, rdtype):
            if rdtype == "NS":
                return ns_answer
            if rdtype == "A":
                return a_answer
            if rdtype == "AAAA":
                raise dns.exception.DNSException("no AAAA")
            return MagicMock()

        mock_global_resolve.side_effect = resolve_side_effect

        settings = SimpleNamespace(
            timeout_seconds=30,
            resolvers=(),
            require_dnssec=False,
            require_authoritative=True,
        )
        validator = Dns01Validator(settings=settings)
        validator.validate(
            token="test-token",
            jwk={"kty": "EC"},
            identifier_type="dns",
            identifier_value="example.com",
        )

    @patch("acmeeh.challenge.dns01.dns.resolver.Resolver")
    def test_multiple_txt_records_one_matching(self, mock_resolver_cls):
        """Multiple TXT records, one of which matches -> success."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        answer = _make_answer(
            [
                "unrelated-txt-value",
                EXPECTED_DIGEST,
                "another-wrong-value",
            ]
        )
        resolver.resolve.return_value = answer

        validator = Dns01Validator(settings=None)
        # Should not raise
        validator.validate(
            token="test-token",
            jwk={"kty": "EC"},
            identifier_type="dns",
            identifier_value="example.com",
        )

    @patch("acmeeh.challenge.dns01.dns.resolver.Resolver")
    def test_custom_resolvers_from_settings(self, mock_resolver_cls):
        """Settings-provided resolvers are applied to the resolver."""
        resolver = MagicMock()
        mock_resolver_cls.return_value = resolver

        answer = _make_answer([EXPECTED_DIGEST])
        resolver.resolve.return_value = answer

        settings = SimpleNamespace(
            timeout_seconds=15,
            resolvers=("8.8.8.8", "1.1.1.1"),
            require_dnssec=False,
            require_authoritative=False,
        )
        validator = Dns01Validator(settings=settings)
        validator.validate(
            token="test-token",
            jwk={"kty": "EC"},
            identifier_type="dns",
            identifier_value="example.com",
        )

        assert resolver.nameservers == ["8.8.8.8", "1.1.1.1"]
        assert resolver.lifetime == 15

    def test_challenge_type(self):
        """Verify the validator reports the correct challenge type."""
        v = Dns01Validator(settings=None)
        assert v.challenge_type == ChallengeType.DNS_01

    def test_supported_identifier_types(self):
        """DNS-01 only supports dns identifiers."""
        v = Dns01Validator(settings=None)
        assert v.supports_identifier("dns")
        assert not v.supports_identifier("ip")
