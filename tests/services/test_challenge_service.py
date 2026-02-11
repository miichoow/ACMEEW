"""Comprehensive tests for acmeeh.services.challenge.ChallengeService.

Covers:
- initiate_validation: lookup failures, terminal/processing states,
  sync success/failure, retry, deferred mode
- process_pending: claims and validates, success/failure/retry paths
- expire_challenges: expires stale challenges and cascades
- _cascade_authz_valid / _cascade_authz_invalid: state cascading
- _check_orders_for_authz / _invalidate_orders_for_authz: order transitions
"""

from __future__ import annotations

from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest

from acmeeh.app.errors import MALFORMED, UNAUTHORIZED, AcmeProblem
from acmeeh.challenge.base import ChallengeError
from acmeeh.core.types import (
    AuthorizationStatus,
    ChallengeStatus,
    ChallengeType,
    IdentifierType,
    OrderStatus,
)
from acmeeh.models.authorization import Authorization
from acmeeh.models.challenge import Challenge
from acmeeh.models.order import Identifier, Order
from acmeeh.services.challenge import ChallengeService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_challenge(
    *,
    challenge_id: UUID | None = None,
    authz_id: UUID | None = None,
    status: ChallengeStatus = ChallengeStatus.PENDING,
    ctype: ChallengeType = ChallengeType.HTTP_01,
    token: str = "test-token",
    retry_count: int = 0,
    error: dict | None = None,
    locked_by: str | None = None,
) -> Challenge:
    return Challenge(
        id=challenge_id or uuid4(),
        authorization_id=authz_id or uuid4(),
        type=ctype,
        token=token,
        status=status,
        retry_count=retry_count,
        error=error,
        locked_by=locked_by,
    )


def _make_authz(
    *,
    authz_id: UUID | None = None,
    account_id: UUID | None = None,
    status: AuthorizationStatus = AuthorizationStatus.PENDING,
    identifier_type: IdentifierType = IdentifierType.DNS,
    identifier_value: str = "example.com",
) -> Authorization:
    return Authorization(
        id=authz_id or uuid4(),
        account_id=account_id or uuid4(),
        identifier_type=identifier_type,
        identifier_value=identifier_value,
        status=status,
    )


def _make_order(
    *,
    order_id: UUID | None = None,
    account_id: UUID | None = None,
    status: OrderStatus = OrderStatus.PENDING,
) -> Order:
    return Order(
        id=order_id or uuid4(),
        account_id=account_id or uuid4(),
        status=status,
        identifiers=(Identifier(type=IdentifierType.DNS, value="example.com"),),
        identifiers_hash="abc123",
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def challenge_repo():
    repo = MagicMock()
    repo.find_by_id.return_value = None
    repo.claim_for_processing.return_value = None
    repo.complete_validation.return_value = None
    repo.retry_challenge.return_value = None
    repo.find_by_authorization.return_value = []
    return repo


@pytest.fixture()
def authz_repo():
    repo = MagicMock()
    repo.find_by_id.return_value = None
    repo.transition_status.return_value = None
    repo.find_expired_pending.return_value = []
    repo.find_by_order.return_value = []
    return repo


@pytest.fixture()
def order_repo():
    repo = MagicMock()
    repo.find_orders_by_authorization.return_value = []
    repo.transition_status.return_value = None
    return repo


@pytest.fixture()
def registry():
    return MagicMock()


@pytest.fixture()
def hook_registry():
    return MagicMock()


@pytest.fixture()
def metrics():
    return MagicMock()


@pytest.fixture()
def challenge_settings():
    settings = MagicMock()
    settings.backoff_base_seconds = 5
    settings.backoff_max_seconds = 300
    return settings


@pytest.fixture()
def service(
    challenge_repo,
    authz_repo,
    order_repo,
    registry,
    hook_registry,
    metrics,
    challenge_settings,
):
    return ChallengeService(
        challenge_repo=challenge_repo,
        authz_repo=authz_repo,
        order_repo=order_repo,
        registry=registry,
        hook_registry=hook_registry,
        metrics=metrics,
        challenge_settings=challenge_settings,
    )


@pytest.fixture()
def jwk():
    return {"kty": "EC", "crv": "P-256", "x": "aaa", "y": "bbb"}


# =========================================================================
# initiate_validation — lookup failures
# =========================================================================


class TestInitiateValidationLookupFailures:
    """_lookup_and_verify edge cases: not found, wrong account, missing authz."""

    def test_challenge_not_found_raises_malformed(
        self,
        service,
        challenge_repo,
        jwk,
    ):
        challenge_repo.find_by_id.return_value = None
        with pytest.raises(AcmeProblem) as exc_info:
            service.initiate_validation(uuid4(), uuid4(), jwk)
        assert exc_info.value.status == 404
        assert MALFORMED in exc_info.value.error_type

    def test_wrong_account_raises_unauthorized(
        self,
        service,
        challenge_repo,
        authz_repo,
        jwk,
    ):
        account_id = uuid4()
        other_account = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(authz_id=authz_id)
        authz = _make_authz(authz_id=authz_id, account_id=other_account)

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz

        with pytest.raises(AcmeProblem) as exc_info:
            service.initiate_validation(challenge.id, account_id, jwk)
        assert exc_info.value.status == 403
        assert UNAUTHORIZED in exc_info.value.error_type

    def test_authz_not_found_raises_malformed(
        self,
        service,
        challenge_repo,
        authz_repo,
        jwk,
    ):
        account_id = uuid4()
        challenge = _make_challenge()
        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = None

        with pytest.raises(AcmeProblem) as exc_info:
            service.initiate_validation(challenge.id, account_id, jwk)
        assert exc_info.value.status == 404
        assert MALFORMED in exc_info.value.error_type


# =========================================================================
# initiate_validation — terminal / processing states
# =========================================================================


class TestInitiateValidationTerminalStates:
    """Already valid/invalid/processing challenges are returned as-is."""

    def test_already_valid_returns_as_is(
        self,
        service,
        challenge_repo,
        authz_repo,
        jwk,
    ):
        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(
            authz_id=authz_id,
            status=ChallengeStatus.VALID,
        )
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz

        result = service.initiate_validation(challenge.id, account_id, jwk)
        assert result is challenge
        challenge_repo.claim_for_processing.assert_not_called()

    def test_already_invalid_returns_as_is(
        self,
        service,
        challenge_repo,
        authz_repo,
        jwk,
    ):
        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(
            authz_id=authz_id,
            status=ChallengeStatus.INVALID,
        )
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz

        result = service.initiate_validation(challenge.id, account_id, jwk)
        assert result is challenge
        challenge_repo.claim_for_processing.assert_not_called()

    def test_claim_fails_returns_current(
        self,
        service,
        challenge_repo,
        authz_repo,
        jwk,
    ):
        """If claim_for_processing returns None (already processing), fetch latest."""
        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(authz_id=authz_id)
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        challenge_repo.find_by_id.side_effect = [challenge, challenge]
        authz_repo.find_by_id.return_value = authz
        challenge_repo.claim_for_processing.return_value = None

        result = service.initiate_validation(challenge.id, account_id, jwk)
        assert result is challenge


# =========================================================================
# initiate_validation — no validator found
# =========================================================================


class TestInitiateValidationNoValidator:
    """When no validator is registered for the challenge type."""

    def test_no_validator_invalidates_challenge(
        self,
        service,
        challenge_repo,
        authz_repo,
        registry,
        jwk,
    ):
        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(authz_id=authz_id)
        claimed = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
        )
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz
        challenge_repo.claim_for_processing.return_value = claimed
        registry.get_validator_or_none.return_value = None

        invalid_challenge = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.INVALID,
        )
        challenge_repo.complete_validation.return_value = invalid_challenge

        result = service.initiate_validation(challenge.id, account_id, jwk)
        assert result is invalid_challenge
        challenge_repo.complete_validation.assert_called_once_with(
            challenge.id,
            unittest_any(),
            success=False,
            error=unittest_any(),
        )


def unittest_any():
    """Return an object that compares equal to anything (like unittest.mock.ANY)."""
    from unittest.mock import ANY

    return ANY


# =========================================================================
# initiate_validation — deferred mode (auto_validate=False)
# =========================================================================


class TestInitiateValidationDeferred:
    """When validator.auto_validate is False, returns claimed challenge."""

    def test_deferred_returns_processing_challenge(
        self,
        service,
        challenge_repo,
        authz_repo,
        registry,
        jwk,
    ):
        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(authz_id=authz_id)
        claimed = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
        )
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz
        challenge_repo.claim_for_processing.return_value = claimed

        validator = MagicMock()
        validator.auto_validate = False
        registry.get_validator_or_none.return_value = validator

        result = service.initiate_validation(challenge.id, account_id, jwk)
        assert result is claimed
        validator.validate.assert_not_called()


# =========================================================================
# initiate_validation — sync validate success
# =========================================================================


class TestInitiateValidationSyncSuccess:
    """Synchronous validation succeeds, cascades to authz valid."""

    def test_sync_success_cascades(
        self,
        service,
        challenge_repo,
        authz_repo,
        order_repo,
        registry,
        hook_registry,
        metrics,
        jwk,
    ):
        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(authz_id=authz_id)
        claimed = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
        )
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz
        challenge_repo.claim_for_processing.return_value = claimed

        validator = MagicMock()
        validator.auto_validate = True
        validator.validate.return_value = None  # success
        validator.cleanup.return_value = None
        registry.get_validator_or_none.return_value = validator

        valid_challenge = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.VALID,
        )
        challenge_repo.complete_validation.return_value = valid_challenge

        result = service.initiate_validation(challenge.id, account_id, jwk)
        assert result is valid_challenge

        # Verify validation was called
        validator.validate.assert_called_once()

        # Verify challenge was marked successful
        challenge_repo.complete_validation.assert_called_once_with(
            challenge.id,
            unittest_any(),
            success=True,
        )

        # Verify hooks dispatched
        hook_registry.dispatch.assert_any_call(
            "challenge.before_validate",
            unittest_any(),
        )
        hook_registry.dispatch.assert_any_call(
            "challenge.after_validate",
            unittest_any(),
        )

        # Verify metrics incremented
        metrics.increment.assert_called_once_with(
            "acmeeh_challenges_validated_total",
            labels={"result": "success"},
        )

        # Verify cascade to authz
        authz_repo.transition_status.assert_called_once_with(
            authz_id,
            AuthorizationStatus.PENDING,
            AuthorizationStatus.VALID,
        )

        # Verify cleanup called
        validator.cleanup.assert_called_once()


# =========================================================================
# initiate_validation — sync validate failure with retry
# =========================================================================


class TestInitiateValidationSyncRetry:
    """Synchronous validation fails with retryable error."""

    def test_retryable_error_retries_challenge(
        self,
        service,
        challenge_repo,
        authz_repo,
        registry,
        hook_registry,
        metrics,
        jwk,
    ):
        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(authz_id=authz_id, retry_count=0)
        claimed = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
        )
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz
        challenge_repo.claim_for_processing.return_value = claimed

        validator = MagicMock()
        validator.auto_validate = True
        validator.max_retries = 3
        validator.validate.side_effect = ChallengeError(
            "DNS resolution timeout",
            retryable=True,
        )
        validator.cleanup.return_value = None
        registry.get_validator_or_none.return_value = validator

        retried = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PENDING,
            retry_count=1,
        )
        challenge_repo.retry_challenge.return_value = retried

        result = service.initiate_validation(challenge.id, account_id, jwk)
        assert result is retried

        # Verify retry was called with correct backoff
        challenge_repo.retry_challenge.assert_called_once_with(
            challenge.id,
            unittest_any(),
            backoff_seconds=5,
        )

        # Verify hook dispatched
        hook_registry.dispatch.assert_any_call(
            "challenge.on_retry",
            unittest_any(),
        )

        # Verify metrics
        metrics.increment.assert_called_once_with(
            "acmeeh_challenges_validated_total",
            labels={"result": "retry"},
        )

        # No cascade should happen on retry
        authz_repo.transition_status.assert_not_called()


# =========================================================================
# initiate_validation — sync validate terminal failure
# =========================================================================


class TestInitiateValidationSyncTerminalFailure:
    """Synchronous validation fails terminally (non-retryable or max retries exceeded)."""

    def test_non_retryable_error_invalidates(
        self,
        service,
        challenge_repo,
        authz_repo,
        registry,
        hook_registry,
        metrics,
        jwk,
    ):
        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(authz_id=authz_id)
        claimed = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
        )
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz
        challenge_repo.claim_for_processing.return_value = claimed

        validator = MagicMock()
        validator.auto_validate = True
        validator.max_retries = 3
        validator.validate.side_effect = ChallengeError(
            "Invalid response",
            retryable=False,
        )
        validator.cleanup.return_value = None
        registry.get_validator_or_none.return_value = validator

        invalid_challenge = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.INVALID,
        )
        challenge_repo.complete_validation.return_value = invalid_challenge

        result = service.initiate_validation(challenge.id, account_id, jwk)
        assert result is invalid_challenge

        # Verify complete_validation called with failure
        challenge_repo.complete_validation.assert_called_once()
        args, kwargs = challenge_repo.complete_validation.call_args
        assert kwargs["success"] is False

        # Verify hook dispatched
        hook_registry.dispatch.assert_any_call(
            "challenge.on_failure",
            unittest_any(),
        )

        # Verify metrics
        metrics.increment.assert_called_once_with(
            "acmeeh_challenges_validated_total",
            labels={"result": "failure"},
        )

        # Verify authz cascade to invalid
        authz_repo.transition_status.assert_called()

    def test_max_retries_exceeded_invalidates(
        self,
        service,
        challenge_repo,
        authz_repo,
        registry,
        hook_registry,
        jwk,
    ):
        account_id = uuid4()
        authz_id = uuid4()
        # Already at max retries
        challenge = _make_challenge(authz_id=authz_id, retry_count=3)
        claimed = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
            retry_count=3,
        )
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz
        challenge_repo.claim_for_processing.return_value = claimed

        validator = MagicMock()
        validator.auto_validate = True
        validator.max_retries = 3  # retry_count == max_retries
        validator.validate.side_effect = ChallengeError(
            "Still failing",
            retryable=True,
        )
        validator.cleanup.return_value = None
        registry.get_validator_or_none.return_value = validator

        invalid_challenge = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.INVALID,
        )
        challenge_repo.complete_validation.return_value = invalid_challenge

        result = service.initiate_validation(challenge.id, account_id, jwk)
        assert result is invalid_challenge

        # Should NOT retry, should invalidate
        challenge_repo.retry_challenge.assert_not_called()
        challenge_repo.complete_validation.assert_called_once()

    def test_unexpected_exception_invalidates(
        self,
        service,
        challenge_repo,
        authz_repo,
        registry,
        hook_registry,
        jwk,
    ):
        """An unexpected (non-ChallengeError) exception invalidates the challenge."""
        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(authz_id=authz_id)
        claimed = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
        )
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz
        challenge_repo.claim_for_processing.return_value = claimed

        validator = MagicMock()
        validator.auto_validate = True
        validator.validate.side_effect = RuntimeError("network error")
        validator.cleanup.return_value = None
        registry.get_validator_or_none.return_value = validator

        invalid_challenge = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.INVALID,
        )
        challenge_repo.complete_validation.return_value = invalid_challenge

        result = service.initiate_validation(challenge.id, account_id, jwk)
        assert result is invalid_challenge

        challenge_repo.complete_validation.assert_called_once()
        args, kwargs = challenge_repo.complete_validation.call_args
        assert kwargs["success"] is False

        # Verify on_failure hook dispatched
        hook_registry.dispatch.assert_any_call(
            "challenge.on_failure",
            unittest_any(),
        )

        # Verify authz cascade to invalid
        authz_repo.transition_status.assert_called()

    def test_cleanup_failure_does_not_propagate(
        self,
        service,
        challenge_repo,
        authz_repo,
        registry,
        jwk,
    ):
        """Cleanup errors are swallowed, validation result is still returned."""
        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(authz_id=authz_id)
        claimed = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
        )
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz
        challenge_repo.claim_for_processing.return_value = claimed

        validator = MagicMock()
        validator.auto_validate = True
        validator.validate.return_value = None  # success
        validator.cleanup.side_effect = RuntimeError("cleanup boom")
        registry.get_validator_or_none.return_value = validator

        valid_challenge = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.VALID,
        )
        challenge_repo.complete_validation.return_value = valid_challenge

        # Should not raise despite cleanup failure
        result = service.initiate_validation(challenge.id, account_id, jwk)
        assert result is valid_challenge


# =========================================================================
# initiate_validation — rate limiter
# =========================================================================


class TestInitiateValidationRateLimiter:
    """Rate limiter integration."""

    def test_rate_limiter_called_when_present(
        self,
        challenge_repo,
        authz_repo,
        order_repo,
        registry,
        jwk,
    ):
        rate_limiter = MagicMock()
        svc = ChallengeService(
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            order_repo=order_repo,
            registry=registry,
            rate_limiter=rate_limiter,
        )

        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(authz_id=authz_id)
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz
        challenge_repo.claim_for_processing.return_value = None
        # claim returns None, so we get a re-fetch path
        challenge_repo.find_by_id.side_effect = [challenge, challenge]

        svc.initiate_validation(challenge.id, account_id, jwk)
        rate_limiter.check.assert_called_once_with(
            str(account_id),
            "challenge_validation",
        )


# =========================================================================
# process_pending
# =========================================================================


class TestProcessPending:
    """process_pending: background worker validation path."""

    def test_challenge_not_found_raises(self, service, challenge_repo, jwk):
        challenge_repo.find_by_id.return_value = None
        with pytest.raises(AcmeProblem) as exc_info:
            service.process_pending(uuid4(), "worker-1", jwk)
        assert exc_info.value.status == 404

    def test_authz_not_found_raises(
        self,
        service,
        challenge_repo,
        authz_repo,
        jwk,
    ):
        challenge = _make_challenge(status=ChallengeStatus.PROCESSING)
        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = None

        with pytest.raises(AcmeProblem) as exc_info:
            service.process_pending(challenge.id, "worker-1", jwk)
        assert exc_info.value.status == 404

    def test_already_valid_returns_as_is(
        self,
        service,
        challenge_repo,
        authz_repo,
        jwk,
    ):
        authz_id = uuid4()
        challenge = _make_challenge(
            authz_id=authz_id,
            status=ChallengeStatus.VALID,
        )
        authz = _make_authz(authz_id=authz_id)

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz

        result = service.process_pending(challenge.id, "worker-1", jwk)
        assert result is challenge

    def test_already_invalid_returns_as_is(
        self,
        service,
        challenge_repo,
        authz_repo,
        jwk,
    ):
        authz_id = uuid4()
        challenge = _make_challenge(
            authz_id=authz_id,
            status=ChallengeStatus.INVALID,
        )
        authz = _make_authz(authz_id=authz_id)

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz

        result = service.process_pending(challenge.id, "worker-1", jwk)
        assert result is challenge

    def test_no_validator_invalidates(
        self,
        service,
        challenge_repo,
        authz_repo,
        registry,
        jwk,
    ):
        authz_id = uuid4()
        challenge = _make_challenge(
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
        )
        authz = _make_authz(authz_id=authz_id)

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz
        registry.get_validator_or_none.return_value = None

        invalid_ch = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.INVALID,
        )
        challenge_repo.complete_validation.return_value = invalid_ch

        result = service.process_pending(challenge.id, "worker-1", jwk)
        assert result is invalid_ch
        challenge_repo.complete_validation.assert_called_once()

    def test_success_cascades(
        self,
        service,
        challenge_repo,
        authz_repo,
        order_repo,
        registry,
        hook_registry,
        metrics,
        jwk,
    ):
        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
        )
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz

        validator = MagicMock()
        validator.auto_validate = True  # doesn't matter for process_pending
        validator.validate.return_value = None
        validator.cleanup.return_value = None
        registry.get_validator_or_none.return_value = validator

        valid_ch = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.VALID,
        )
        challenge_repo.complete_validation.return_value = valid_ch

        result = service.process_pending(challenge.id, "worker-1", jwk)
        assert result is valid_ch
        validator.validate.assert_called_once()
        authz_repo.transition_status.assert_called_once_with(
            authz_id,
            AuthorizationStatus.PENDING,
            AuthorizationStatus.VALID,
        )

    def test_retryable_failure_retries(
        self,
        service,
        challenge_repo,
        authz_repo,
        registry,
        jwk,
    ):
        authz_id = uuid4()
        challenge = _make_challenge(
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
            retry_count=1,
        )
        authz = _make_authz(authz_id=authz_id)

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz

        validator = MagicMock()
        validator.max_retries = 5
        validator.validate.side_effect = ChallengeError(
            "Timeout",
            retryable=True,
        )
        validator.cleanup.return_value = None
        registry.get_validator_or_none.return_value = validator

        retried = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PENDING,
            retry_count=2,
        )
        challenge_repo.retry_challenge.return_value = retried

        result = service.process_pending(challenge.id, "worker-1", jwk)
        assert result is retried
        # Backoff: 5 * 2^1 = 10
        challenge_repo.retry_challenge.assert_called_once_with(
            challenge.id,
            "worker-1",
            backoff_seconds=10,
        )

    def test_terminal_failure_invalidates(
        self,
        service,
        challenge_repo,
        authz_repo,
        registry,
        jwk,
    ):
        authz_id = uuid4()
        challenge = _make_challenge(
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
        )
        authz = _make_authz(authz_id=authz_id)

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz

        validator = MagicMock()
        validator.max_retries = 3
        validator.validate.side_effect = ChallengeError(
            "Bad token",
            retryable=False,
        )
        validator.cleanup.return_value = None
        registry.get_validator_or_none.return_value = validator

        invalid_ch = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.INVALID,
        )
        challenge_repo.complete_validation.return_value = invalid_ch

        result = service.process_pending(challenge.id, "worker-1", jwk)
        assert result is invalid_ch
        challenge_repo.complete_validation.assert_called_once()
        authz_repo.transition_status.assert_called()


# =========================================================================
# expire_challenges
# =========================================================================


class TestExpireChallenges:
    """expire_challenges: expires stale challenges and cascades."""

    def test_no_expired_authzs(self, service, authz_repo):
        authz_repo.find_expired_pending.return_value = []
        count = service.expire_challenges()
        assert count == 0

    def test_expires_pending_challenges(
        self,
        service,
        challenge_repo,
        authz_repo,
        order_repo,
        metrics,
    ):
        authz_id = uuid4()
        authz = _make_authz(authz_id=authz_id)
        authz_repo.find_expired_pending.return_value = [authz]

        ch1 = _make_challenge(
            authz_id=authz_id,
            status=ChallengeStatus.PENDING,
        )
        ch2 = _make_challenge(
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
        )
        ch3 = _make_challenge(
            authz_id=authz_id,
            status=ChallengeStatus.VALID,
        )
        challenge_repo.find_by_authorization.return_value = [ch1, ch2, ch3]
        challenge_repo.claim_for_processing.return_value = _make_challenge(
            status=ChallengeStatus.PROCESSING,
        )
        order_repo.find_orders_by_authorization.return_value = []

        count = service.expire_challenges()
        # ch1 (pending) and ch2 (processing) should be expired, ch3 (valid) skipped
        assert count == 2

        # Verify authz transitioned to expired
        authz_repo.transition_status.assert_called_once_with(
            authz_id,
            AuthorizationStatus.PENDING,
            AuthorizationStatus.EXPIRED,
        )

        # Verify metrics
        assert metrics.increment.call_count == 2
        metrics.increment.assert_called_with("acmeeh_challenges_expired_total")

    def test_claim_failure_skips_challenge(
        self,
        service,
        challenge_repo,
        authz_repo,
        order_repo,
    ):
        authz_id = uuid4()
        authz = _make_authz(authz_id=authz_id)
        authz_repo.find_expired_pending.return_value = [authz]

        ch = _make_challenge(authz_id=authz_id, status=ChallengeStatus.PENDING)
        challenge_repo.find_by_authorization.return_value = [ch]
        challenge_repo.claim_for_processing.return_value = None  # claim fails
        order_repo.find_orders_by_authorization.return_value = []

        count = service.expire_challenges()
        assert count == 0  # Couldn't claim, so not counted

        # complete_validation should NOT be called
        challenge_repo.complete_validation.assert_not_called()

    def test_expire_invalidates_orders(
        self,
        service,
        challenge_repo,
        authz_repo,
        order_repo,
    ):
        authz_id = uuid4()
        authz = _make_authz(authz_id=authz_id)
        authz_repo.find_expired_pending.return_value = [authz]

        challenge_repo.find_by_authorization.return_value = []

        pending_order = _make_order(status=OrderStatus.PENDING)
        order_repo.find_orders_by_authorization.return_value = [pending_order]

        service.expire_challenges()

        # Order should be transitioned to invalid
        order_repo.transition_status.assert_called_once()
        args, kwargs = order_repo.transition_status.call_args
        assert args[1] == OrderStatus.PENDING
        assert args[2] == OrderStatus.INVALID


# =========================================================================
# _cascade_authz_valid / _cascade_authz_invalid
# =========================================================================


class TestCascadeAuthzValid:
    """_cascade_authz_valid: transitions authz and checks orders."""

    def test_valid_challenge_makes_authz_valid(
        self,
        service,
        authz_repo,
        order_repo,
    ):
        authz_id = uuid4()
        authz_repo.transition_status.return_value = _make_authz(
            authz_id=authz_id,
            status=AuthorizationStatus.VALID,
        )
        order_repo.find_orders_by_authorization.return_value = []

        service._cascade_authz_valid(authz_id)

        authz_repo.transition_status.assert_called_once_with(
            authz_id,
            AuthorizationStatus.PENDING,
            AuthorizationStatus.VALID,
        )

    def test_all_authzs_valid_transitions_order_to_ready(
        self,
        service,
        authz_repo,
        order_repo,
    ):
        authz_id = uuid4()
        order_id = uuid4()
        order = _make_order(order_id=order_id, status=OrderStatus.PENDING)

        authz_repo.transition_status.return_value = _make_authz(
            authz_id=authz_id,
            status=AuthorizationStatus.VALID,
        )
        order_repo.find_orders_by_authorization.return_value = [order]

        # All authzs for order are valid
        authz_repo.find_by_order.return_value = [
            _make_authz(status=AuthorizationStatus.VALID),
            _make_authz(status=AuthorizationStatus.VALID),
        ]
        order_repo.transition_status.return_value = _make_order(
            order_id=order_id,
            status=OrderStatus.READY,
        )

        service._cascade_authz_valid(authz_id)

        order_repo.transition_status.assert_called_once_with(
            order_id,
            OrderStatus.PENDING,
            OrderStatus.READY,
        )

    def test_not_all_authzs_valid_does_not_transition_order(
        self,
        service,
        authz_repo,
        order_repo,
    ):
        authz_id = uuid4()
        order = _make_order(status=OrderStatus.PENDING)

        authz_repo.transition_status.return_value = _make_authz(
            authz_id=authz_id,
            status=AuthorizationStatus.VALID,
        )
        order_repo.find_orders_by_authorization.return_value = [order]

        # One authz still pending
        authz_repo.find_by_order.return_value = [
            _make_authz(status=AuthorizationStatus.VALID),
            _make_authz(status=AuthorizationStatus.PENDING),
        ]

        service._cascade_authz_valid(authz_id)

        order_repo.transition_status.assert_not_called()

    def test_non_pending_order_skipped(
        self,
        service,
        authz_repo,
        order_repo,
    ):
        authz_id = uuid4()
        # Order is already READY, should be skipped
        order = _make_order(status=OrderStatus.READY)

        authz_repo.transition_status.return_value = _make_authz(
            authz_id=authz_id,
            status=AuthorizationStatus.VALID,
        )
        order_repo.find_orders_by_authorization.return_value = [order]

        service._cascade_authz_valid(authz_id)

        authz_repo.find_by_order.assert_not_called()
        order_repo.transition_status.assert_not_called()


class TestCascadeAuthzInvalid:
    """_cascade_authz_invalid: transitions authz and invalidates orders."""

    def test_invalid_challenge_makes_authz_invalid(
        self,
        service,
        authz_repo,
        order_repo,
    ):
        authz_id = uuid4()
        authz = _make_authz(authz_id=authz_id)
        authz_repo.find_by_id.return_value = authz
        authz_repo.transition_status.return_value = _make_authz(
            authz_id=authz_id,
            status=AuthorizationStatus.INVALID,
        )
        order_repo.find_orders_by_authorization.return_value = []

        service._cascade_authz_invalid(authz_id)

        authz_repo.transition_status.assert_called_once_with(
            authz_id,
            AuthorizationStatus.PENDING,
            AuthorizationStatus.INVALID,
        )

    def test_invalidation_cascades_to_pending_orders(
        self,
        service,
        authz_repo,
        order_repo,
    ):
        authz_id = uuid4()
        order_id = uuid4()
        authz = _make_authz(authz_id=authz_id)
        order = _make_order(order_id=order_id, status=OrderStatus.PENDING)

        authz_repo.find_by_id.return_value = authz
        authz_repo.transition_status.return_value = _make_authz(
            authz_id=authz_id,
            status=AuthorizationStatus.INVALID,
        )
        order_repo.find_orders_by_authorization.return_value = [order]
        order_repo.transition_status.return_value = _make_order(
            order_id=order_id,
            status=OrderStatus.INVALID,
        )

        service._cascade_authz_invalid(authz_id)

        order_repo.transition_status.assert_called_once()
        args, kwargs = order_repo.transition_status.call_args
        assert args[0] == order_id
        assert args[1] == OrderStatus.PENDING
        assert args[2] == OrderStatus.INVALID
        assert "error" in kwargs

    def test_non_pending_orders_not_invalidated(
        self,
        service,
        authz_repo,
        order_repo,
    ):
        authz_id = uuid4()
        authz = _make_authz(authz_id=authz_id)
        valid_order = _make_order(status=OrderStatus.VALID)
        ready_order = _make_order(status=OrderStatus.READY)

        authz_repo.find_by_id.return_value = authz
        authz_repo.transition_status.return_value = _make_authz(
            authz_id=authz_id,
            status=AuthorizationStatus.INVALID,
        )
        order_repo.find_orders_by_authorization.return_value = [
            valid_order,
            ready_order,
        ]

        service._cascade_authz_invalid(authz_id)

        order_repo.transition_status.assert_not_called()

    def test_subproblems_include_identifier_info(
        self,
        service,
        authz_repo,
        order_repo,
    ):
        authz_id = uuid4()
        order_id = uuid4()
        authz = _make_authz(
            authz_id=authz_id,
            identifier_type=IdentifierType.DNS,
            identifier_value="fail.example.com",
        )
        order = _make_order(order_id=order_id, status=OrderStatus.PENDING)

        authz_repo.find_by_id.return_value = authz
        authz_repo.transition_status.return_value = _make_authz(
            authz_id=authz_id,
            status=AuthorizationStatus.INVALID,
        )
        order_repo.find_orders_by_authorization.return_value = [order]
        order_repo.transition_status.return_value = _make_order(
            order_id=order_id,
            status=OrderStatus.INVALID,
        )

        service._cascade_authz_invalid(authz_id)

        # Verify the error dict includes subproblems
        call_kwargs = order_repo.transition_status.call_args[1]
        error = call_kwargs["error"]
        assert "subproblems" in error
        subproblem = error["subproblems"][0]
        assert subproblem["identifier"]["value"] == "fail.example.com"
        assert subproblem["identifier"]["type"] == "dns"


# =========================================================================
# Service without optional dependencies
# =========================================================================


class TestServiceNoOptionalDeps:
    """Service works when hooks, metrics, rate_limiter are None."""

    def test_sync_success_without_hooks_and_metrics(
        self,
        challenge_repo,
        authz_repo,
        order_repo,
        registry,
    ):
        svc = ChallengeService(
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            order_repo=order_repo,
            registry=registry,
            hook_registry=None,
            metrics=None,
            rate_limiter=None,
        )

        account_id = uuid4()
        authz_id = uuid4()
        challenge = _make_challenge(authz_id=authz_id)
        authz = _make_authz(authz_id=authz_id, account_id=account_id)

        challenge_repo.find_by_id.return_value = challenge
        authz_repo.find_by_id.return_value = authz

        claimed = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.PROCESSING,
        )
        challenge_repo.claim_for_processing.return_value = claimed

        validator = MagicMock()
        validator.auto_validate = True
        validator.validate.return_value = None
        validator.cleanup.return_value = None
        registry.get_validator_or_none.return_value = validator

        valid_ch = _make_challenge(
            challenge_id=challenge.id,
            authz_id=authz_id,
            status=ChallengeStatus.VALID,
        )
        challenge_repo.complete_validation.return_value = valid_ch
        authz_repo.transition_status.return_value = _make_authz(
            status=AuthorizationStatus.VALID,
        )
        order_repo.find_orders_by_authorization.return_value = []

        jwk = {"kty": "EC"}
        result = svc.initiate_validation(challenge.id, account_id, jwk)
        assert result is valid_ch

    def test_expire_without_metrics(
        self,
        challenge_repo,
        authz_repo,
        order_repo,
        registry,
    ):
        svc = ChallengeService(
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            order_repo=order_repo,
            registry=registry,
            metrics=None,
        )

        authz_id = uuid4()
        authz = _make_authz(authz_id=authz_id)
        authz_repo.find_expired_pending.return_value = [authz]

        ch = _make_challenge(authz_id=authz_id, status=ChallengeStatus.PENDING)
        challenge_repo.find_by_authorization.return_value = [ch]
        challenge_repo.claim_for_processing.return_value = _make_challenge(
            status=ChallengeStatus.PROCESSING,
        )
        order_repo.find_orders_by_authorization.return_value = []

        count = svc.expire_challenges()
        assert count == 1
