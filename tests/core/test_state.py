"""Unit tests for acmeeh.core.state — ACME resource state machines."""

from __future__ import annotations

import logging

import pytest

from acmeeh.core.state import (
    AUTHORIZATION_TRANSITIONS,
    CHALLENGE_TRANSITIONS,
    ORDER_TRANSITIONS,
    assert_transition,
    log_transition,
)
from acmeeh.core.types import (
    AuthorizationStatus,
    ChallengeStatus,
    OrderStatus,
)

# ---------------------------------------------------------------------------
# TestOrderTransitions
# ---------------------------------------------------------------------------


class TestOrderTransitions:
    @pytest.mark.parametrize(
        "current,target",
        [
            (OrderStatus.PENDING, OrderStatus.READY),
            (OrderStatus.PENDING, OrderStatus.INVALID),
            (OrderStatus.READY, OrderStatus.PROCESSING),
            (OrderStatus.READY, OrderStatus.INVALID),
            (OrderStatus.PROCESSING, OrderStatus.VALID),
            (OrderStatus.PROCESSING, OrderStatus.INVALID),
        ],
    )
    def test_valid_transitions(self, current, target):
        assert_transition(current, target, ORDER_TRANSITIONS)  # no exception

    @pytest.mark.parametrize("terminal", [OrderStatus.VALID, OrderStatus.INVALID])
    def test_terminal_states_reject_everything(self, terminal):
        for target in OrderStatus:
            if target == terminal:
                continue
            with pytest.raises(ValueError, match="Invalid transition"):
                assert_transition(terminal, target, ORDER_TRANSITIONS)

    def test_invalid_transition_pending_to_valid(self):
        with pytest.raises(ValueError, match="Invalid transition"):
            assert_transition(OrderStatus.PENDING, OrderStatus.VALID, ORDER_TRANSITIONS)

    def test_unknown_status(self):
        with pytest.raises(ValueError, match="Unknown status"):
            assert_transition("bogus", OrderStatus.VALID, ORDER_TRANSITIONS)


# ---------------------------------------------------------------------------
# TestAuthorizationTransitions
# ---------------------------------------------------------------------------


class TestAuthorizationTransitions:
    @pytest.mark.parametrize(
        "current,target",
        [
            (AuthorizationStatus.PENDING, AuthorizationStatus.VALID),
            (AuthorizationStatus.PENDING, AuthorizationStatus.INVALID),
            (AuthorizationStatus.PENDING, AuthorizationStatus.DEACTIVATED),
            (AuthorizationStatus.PENDING, AuthorizationStatus.EXPIRED),
            (AuthorizationStatus.VALID, AuthorizationStatus.DEACTIVATED),
            (AuthorizationStatus.VALID, AuthorizationStatus.REVOKED),
        ],
    )
    def test_valid_transitions(self, current, target):
        assert_transition(current, target, AUTHORIZATION_TRANSITIONS)

    @pytest.mark.parametrize(
        "terminal",
        [
            AuthorizationStatus.INVALID,
            AuthorizationStatus.DEACTIVATED,
            AuthorizationStatus.EXPIRED,
            AuthorizationStatus.REVOKED,
        ],
    )
    def test_terminal_states(self, terminal):
        for target in AuthorizationStatus:
            if target == terminal:
                continue
            with pytest.raises(ValueError, match="Invalid transition"):
                assert_transition(terminal, target, AUTHORIZATION_TRANSITIONS)

    def test_invalid_transition_pending_to_revoked(self):
        with pytest.raises(ValueError, match="Invalid transition"):
            assert_transition(
                AuthorizationStatus.PENDING,
                AuthorizationStatus.REVOKED,
                AUTHORIZATION_TRANSITIONS,
            )


# ---------------------------------------------------------------------------
# TestChallengeTransitions
# ---------------------------------------------------------------------------


class TestChallengeTransitions:
    @pytest.mark.parametrize(
        "current,target",
        [
            (ChallengeStatus.PENDING, ChallengeStatus.PROCESSING),
            (ChallengeStatus.PROCESSING, ChallengeStatus.VALID),
            (ChallengeStatus.PROCESSING, ChallengeStatus.INVALID),
            (ChallengeStatus.PROCESSING, ChallengeStatus.PENDING),  # retry
        ],
    )
    def test_valid_transitions(self, current, target):
        assert_transition(current, target, CHALLENGE_TRANSITIONS)

    @pytest.mark.parametrize("terminal", [ChallengeStatus.VALID, ChallengeStatus.INVALID])
    def test_terminal_states(self, terminal):
        for target in ChallengeStatus:
            if target == terminal:
                continue
            with pytest.raises(ValueError, match="Invalid transition"):
                assert_transition(terminal, target, CHALLENGE_TRANSITIONS)


# ---------------------------------------------------------------------------
# TestLogTransition
# ---------------------------------------------------------------------------


class TestLogTransition:
    def test_emits_structured_log(self, caplog):
        with caplog.at_level(logging.INFO, logger="acmeeh.core.state"):
            log_transition("order", "abc-123", OrderStatus.PENDING, OrderStatus.READY)
        assert "order" in caplog.text
        assert "abc-123" in caplog.text
        assert "pending" in caplog.text
        assert "ready" in caplog.text

    def test_reason_included(self, caplog):
        with caplog.at_level(logging.INFO, logger="acmeeh.core.state"):
            log_transition(
                "authorization",
                "xyz",
                AuthorizationStatus.PENDING,
                AuthorizationStatus.INVALID,
                reason="challenge failed",
            )
        assert "challenge failed" in caplog.text

    def test_non_enum_status(self, caplog):
        with caplog.at_level(logging.INFO, logger="acmeeh.core.state"):
            log_transition("challenge", "id1", "old_status", "new_status")
        assert "old_status" in caplog.text
        assert "new_status" in caplog.text
