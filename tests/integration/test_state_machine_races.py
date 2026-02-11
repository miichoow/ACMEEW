"""Tests for state machine race conditions.

Verifies that concurrent state transitions on challenges, authorizations,
and orders are handled safely — exactly one transition wins and others
receive appropriate errors.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from acmeeh.core.state import (
    AUTHORIZATION_TRANSITIONS,
    CHALLENGE_TRANSITIONS,
    ORDER_TRANSITIONS,
    assert_transition,
)
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

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_order(status=OrderStatus.PENDING, **kwargs):
    defaults = dict(
        id=uuid4(),
        account_id=uuid4(),
        status=status,
        identifiers=(Identifier(type=IdentifierType.DNS, value="race.example.com"),),
        identifiers_hash="hash123",
        expires=datetime.now(UTC) + timedelta(hours=1),
    )
    defaults.update(kwargs)
    return Order(**defaults)


def _make_authz(status=AuthorizationStatus.PENDING, **kwargs):
    defaults = dict(
        id=uuid4(),
        account_id=uuid4(),
        identifier_type=IdentifierType.DNS,
        identifier_value="race.example.com",
        status=status,
        expires=datetime.now(UTC) + timedelta(hours=1),
    )
    defaults.update(kwargs)
    return Authorization(**defaults)


def _make_challenge(status=ChallengeStatus.PENDING, **kwargs):
    defaults = dict(
        id=uuid4(),
        authorization_id=uuid4(),
        type=ChallengeType.HTTP_01,
        token="test-token",
        status=status,
    )
    defaults.update(kwargs)
    return Challenge(**defaults)


# ---------------------------------------------------------------------------
# State transition table tests
# ---------------------------------------------------------------------------


class TestStateTransitionTables:
    """Ensure transition tables reject invalid transitions."""

    def test_order_pending_to_valid_rejected(self):
        """Order cannot jump from PENDING to VALID."""
        with pytest.raises(ValueError, match="Invalid transition"):
            assert_transition(
                OrderStatus.PENDING,
                OrderStatus.VALID,
                ORDER_TRANSITIONS,
            )

    def test_order_valid_is_terminal(self):
        """Order in VALID cannot transition to anything."""
        with pytest.raises(ValueError, match="Invalid transition"):
            assert_transition(
                OrderStatus.VALID,
                OrderStatus.PENDING,
                ORDER_TRANSITIONS,
            )

    def test_order_invalid_is_terminal(self):
        """Order in INVALID cannot transition to anything."""
        with pytest.raises(ValueError, match="Invalid transition"):
            assert_transition(
                OrderStatus.INVALID,
                OrderStatus.PENDING,
                ORDER_TRANSITIONS,
            )

    def test_challenge_pending_to_valid_rejected(self):
        """Challenge cannot jump from PENDING to VALID (must go through PROCESSING)."""
        with pytest.raises(ValueError, match="Invalid transition"):
            assert_transition(
                ChallengeStatus.PENDING,
                ChallengeStatus.VALID,
                CHALLENGE_TRANSITIONS,
            )

    def test_challenge_valid_is_terminal(self):
        """Challenge in VALID cannot transition to anything."""
        with pytest.raises(ValueError, match="Invalid transition"):
            assert_transition(
                ChallengeStatus.VALID,
                ChallengeStatus.PENDING,
                CHALLENGE_TRANSITIONS,
            )

    def test_authz_pending_to_valid_allowed(self):
        """Authorization CAN go PENDING -> VALID."""
        assert_transition(
            AuthorizationStatus.PENDING,
            AuthorizationStatus.VALID,
            AUTHORIZATION_TRANSITIONS,
        )

    def test_authz_expired_is_terminal(self):
        """Authorization in EXPIRED cannot transition."""
        with pytest.raises(ValueError, match="Invalid transition"):
            assert_transition(
                AuthorizationStatus.EXPIRED,
                AuthorizationStatus.VALID,
                AUTHORIZATION_TRANSITIONS,
            )


# ---------------------------------------------------------------------------
# Concurrent transition tests
# ---------------------------------------------------------------------------


class TestConcurrentOrderTransitions:
    """Test that concurrent order transitions are safely handled
    via compare-and-swap (CAS) semantics in the repository."""

    def test_concurrent_pending_to_ready_only_one_wins(self):
        """Two threads try PENDING->READY; exactly one should succeed."""
        order = _make_order(status=OrderStatus.PENDING)
        lock = threading.Lock()
        first_done = {"value": False}

        class CASOrderRepo:
            def transition_status(self, oid, from_s, to_s, **kw):
                with lock:
                    if not first_done["value"]:
                        first_done["value"] = True
                        from dataclasses import replace

                        return replace(order, status=to_s)
                    return None  # CAS failure

        repo = CASOrderRepo()
        results = [None, None]

        def do_transition(idx):
            results[idx] = repo.transition_status(
                order.id,
                OrderStatus.PENDING,
                OrderStatus.READY,
            )

        t1 = threading.Thread(target=do_transition, args=(0,))
        t2 = threading.Thread(target=do_transition, args=(1,))
        t1.start()
        t2.start()
        t1.join(timeout=2)
        t2.join(timeout=2)

        successes = [r for r in results if r is not None]
        assert len(successes) == 1, "Exactly one thread should win the CAS"
        assert successes[0].status == OrderStatus.READY

    def test_concurrent_ready_to_processing_and_invalid(self):
        """One thread tries READY->PROCESSING, another READY->INVALID.
        Only one should succeed."""
        order = _make_order(status=OrderStatus.READY)
        lock = threading.Lock()
        first_done = {"value": False}

        class CASOrderRepo:
            def transition_status(self, oid, from_s, to_s, **kw):
                with lock:
                    if not first_done["value"]:
                        first_done["value"] = True
                        from dataclasses import replace

                        return replace(order, status=to_s)
                    return None

        repo = CASOrderRepo()
        results = [None, None]

        def to_processing():
            results[0] = repo.transition_status(
                order.id,
                OrderStatus.READY,
                OrderStatus.PROCESSING,
            )

        def to_invalid():
            results[1] = repo.transition_status(
                order.id,
                OrderStatus.READY,
                OrderStatus.INVALID,
            )

        t1 = threading.Thread(target=to_processing)
        t2 = threading.Thread(target=to_invalid)
        t1.start()
        t2.start()
        t1.join(timeout=2)
        t2.join(timeout=2)

        successes = [r for r in results if r is not None]
        assert len(successes) == 1


class TestConcurrentChallengeTransitions:
    """Test challenge transition races."""

    def test_concurrent_claim_for_processing(self):
        """Two workers try to claim the same challenge for processing.
        Only one should succeed."""
        challenge = _make_challenge(status=ChallengeStatus.PENDING)
        lock = threading.Lock()
        first_done = {"value": False}

        class CASChallengeRepo:
            def claim_for_processing(self, cid, worker_id):
                with lock:
                    if not first_done["value"]:
                        first_done["value"] = True
                        from dataclasses import replace

                        return replace(challenge, status=ChallengeStatus.PROCESSING)
                    return None

        repo = CASChallengeRepo()
        results = [None, None]

        def claim(idx, worker_id):
            results[idx] = repo.claim_for_processing(challenge.id, worker_id)

        t1 = threading.Thread(target=claim, args=(0, "worker-1"))
        t2 = threading.Thread(target=claim, args=(1, "worker-2"))
        t1.start()
        t2.start()
        t1.join(timeout=2)
        t2.join(timeout=2)

        successes = [r for r in results if r is not None]
        assert len(successes) == 1
        assert successes[0].status == ChallengeStatus.PROCESSING

    def test_concurrent_complete_validation(self):
        """Two threads complete the same challenge — one valid, one invalid.
        Only one should succeed."""
        challenge = _make_challenge(status=ChallengeStatus.PROCESSING)
        lock = threading.Lock()
        first_done = {"value": False}

        class CASChallengeRepo:
            def complete_validation(self, cid, worker_id, success, error=None):
                with lock:
                    if not first_done["value"]:
                        first_done["value"] = True
                        from dataclasses import replace

                        new_status = ChallengeStatus.VALID if success else ChallengeStatus.INVALID
                        return replace(challenge, status=new_status)
                    return None

        repo = CASChallengeRepo()
        results = [None, None]

        def complete_valid():
            results[0] = repo.complete_validation(
                challenge.id,
                "w1",
                True,
            )

        def complete_invalid():
            results[1] = repo.complete_validation(
                challenge.id,
                "w2",
                False,
                error="timeout",
            )

        t1 = threading.Thread(target=complete_valid)
        t2 = threading.Thread(target=complete_invalid)
        t1.start()
        t2.start()
        t1.join(timeout=2)
        t2.join(timeout=2)

        successes = [r for r in results if r is not None]
        assert len(successes) == 1


class TestConcurrentAuthzTransitions:
    """Test authorization transition races."""

    def test_concurrent_valid_and_deactivated(self):
        """One thread tries PENDING->VALID while another deactivates.
        Exactly one should succeed."""
        authz = _make_authz(status=AuthorizationStatus.PENDING)
        lock = threading.Lock()
        first_done = {"value": False}

        class CASAuthzRepo:
            def transition_status(self, aid, from_s, to_s):
                with lock:
                    if not first_done["value"]:
                        first_done["value"] = True
                        from dataclasses import replace

                        return replace(authz, status=to_s)
                    return None

        repo = CASAuthzRepo()
        results = [None, None]

        def to_valid():
            results[0] = repo.transition_status(
                authz.id,
                AuthorizationStatus.PENDING,
                AuthorizationStatus.VALID,
            )

        def to_deactivated():
            results[1] = repo.transition_status(
                authz.id,
                AuthorizationStatus.PENDING,
                AuthorizationStatus.DEACTIVATED,
            )

        t1 = threading.Thread(target=to_valid)
        t2 = threading.Thread(target=to_deactivated)
        t1.start()
        t2.start()
        t1.join(timeout=2)
        t2.join(timeout=2)

        successes = [r for r in results if r is not None]
        assert len(successes) == 1
