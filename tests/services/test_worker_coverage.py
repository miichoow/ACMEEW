"""Tests targeting uncovered lines in CleanupWorker, ChallengeWorker, and ExpirationWorker.

Covers: leader election (acquire/release with DB), constructor task registration
for audit retention / rate-limit GC / data retention, static cleanup methods,
ChallengeWorker._poll internals, ExpirationWorker._check_expirations and
_try_claim_notice, and the _run loop when leader acquisition fails or the
stop event fires mid-iteration.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from acmeeh.metrics.collector import MetricsCollector
from acmeeh.services.cleanup_worker import CleanupWorker, _CleanupTask
from acmeeh.services.expiration_worker import ExpirationWorker
from acmeeh.services.workers import ChallengeWorker

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_one_iteration(worker) -> None:
    """Run the worker loop for exactly one iteration then stop."""
    original_wait = worker._stop_event.wait

    def _wait_then_stop(timeout=None):
        worker._stop_event.set()

    worker._stop_event.wait = _wait_then_stop
    worker._run()
    worker._stop_event.wait = original_wait


def _make_retention_settings() -> MagicMock:
    """Create a settings mock with retention and audit_retention enabled."""
    settings = MagicMock()

    # retention sub-object
    settings.retention.enabled = True
    settings.retention.cleanup_interval_seconds = 3600
    settings.retention.expired_authz_max_age_days = 90
    settings.retention.invalid_challenge_max_age_days = 30
    settings.retention.invalid_order_max_age_days = 60
    settings.retention.expiration_notice_max_age_days = 180
    settings.retention.cleanup_loop_interval_seconds = 60

    # audit_retention sub-object
    settings.audit_retention.enabled = True
    settings.audit_retention.cleanup_interval_seconds = 7200
    settings.audit_retention.max_age_days = 365

    # nonce (needed if nonce_service provided)
    settings.nonce.gc_interval_seconds = 120

    # order (needed if order_repo provided)
    settings.order.cleanup_interval_seconds = 300
    settings.order.stale_processing_threshold_seconds = 600

    # security.rate_limits for rate limiter
    settings.security.rate_limits.gc_interval_seconds = 500

    return settings


def _make_notification_settings(
    enabled: bool = True,
    warning_days: list[int] | None = None,
    interval: int = 60,
) -> MagicMock:
    """Create a NotificationSettings mock."""
    s = MagicMock()
    s.enabled = enabled
    s.expiration_warning_days = warning_days if warning_days is not None else [30, 7]
    s.expiration_check_interval_seconds = interval
    return s


def _make_challenge(
    *,
    status: str = "pending",
    retry_count: int = 1,
    next_retry_at=None,
    authorization_id=None,
    challenge_id=None,
) -> MagicMock:
    """Create a challenge mock mimicking the frozen dataclass."""
    c = MagicMock()
    from acmeeh.core.types import ChallengeStatus

    c.id = challenge_id or uuid.uuid4()
    c.authorization_id = authorization_id or uuid.uuid4()
    c.status = ChallengeStatus(status)
    c.retry_count = retry_count
    c.next_retry_at = next_retry_at
    return c


# ===========================================================================
# CleanupWorker — constructor task registration
# ===========================================================================


class TestCleanupWorkerTaskRegistration:
    """Tests that __init__ registers the correct tasks based on parameters."""

    def test_audit_retention_task_registered(self):
        """Lines 122-129: audit_retention task added when enabled."""
        settings = _make_retention_settings()
        db = MagicMock()
        worker = CleanupWorker(settings=settings, db=db)
        task_names = [t.name for t in worker._tasks]
        assert "audit_retention" in task_names

    def test_audit_retention_not_registered_when_disabled(self):
        """Audit retention task not registered when audit_retention.enabled is False."""
        settings = _make_retention_settings()
        settings.audit_retention.enabled = False
        db = MagicMock()
        worker = CleanupWorker(settings=settings, db=db)
        task_names = [t.name for t in worker._tasks]
        assert "audit_retention" not in task_names

    def test_rate_limit_gc_registered_with_limiter(self):
        """Lines 132-140: rate_limit_gc task added when db_rate_limiter given."""
        limiter = MagicMock()
        settings = _make_retention_settings()
        worker = CleanupWorker(db_rate_limiter=limiter, settings=settings)
        task_names = [t.name for t in worker._tasks]
        assert "rate_limit_gc" in task_names

    def test_rate_limit_gc_interval_from_settings(self):
        """Lines 133-136: gc_interval comes from settings when available."""
        limiter = MagicMock()
        settings = _make_retention_settings()
        settings.security.rate_limits.gc_interval_seconds = 999
        worker = CleanupWorker(db_rate_limiter=limiter, settings=settings)
        task = next(t for t in worker._tasks if t.name == "rate_limit_gc")
        assert task.interval_seconds == 999

    def test_rate_limit_gc_default_interval_without_settings(self):
        """Lines 133: gc_interval defaults to 300 when no settings."""
        limiter = MagicMock()
        worker = CleanupWorker(db_rate_limiter=limiter)
        task = next(t for t in worker._tasks if t.name == "rate_limit_gc")
        assert task.interval_seconds == 300

    def test_data_retention_tasks_registered(self):
        """Lines 142-172: all four retention tasks registered when enabled."""
        settings = _make_retention_settings()
        db = MagicMock()
        worker = CleanupWorker(settings=settings, db=db)
        task_names = [t.name for t in worker._tasks]
        assert "authz_retention" in task_names
        assert "challenge_retention" in task_names
        assert "order_retention" in task_names
        assert "notice_retention" in task_names

    def test_data_retention_not_registered_when_disabled(self):
        """Retention tasks not registered when retention.enabled is False."""
        settings = _make_retention_settings()
        settings.retention.enabled = False
        db = MagicMock()
        worker = CleanupWorker(settings=settings, db=db)
        task_names = [t.name for t in worker._tasks]
        for name in (
            "authz_retention",
            "challenge_retention",
            "order_retention",
            "notice_retention",
        ):
            assert name not in task_names


# ===========================================================================
# CleanupWorker — leader election
# ===========================================================================


class TestCleanupWorkerLeaderElection:
    """Leader election via advisory locks."""

    def test_try_acquire_leader_no_db_returns_true(self):
        """Line 204-205: no DB means always leader."""
        worker = CleanupWorker()
        assert worker._try_acquire_leader() is True

    def test_try_acquire_leader_with_db_success(self):
        """Lines 206-212: DB fetch_value returns True -> leader acquired."""
        db = MagicMock()
        db.fetch_value.return_value = True
        worker = CleanupWorker(db=db)
        assert worker._try_acquire_leader() is True
        db.fetch_value.assert_called_once()

    def test_try_acquire_leader_with_db_returns_false(self):
        """Lines 206-212: DB fetch_value returns False -> not leader."""
        db = MagicMock()
        db.fetch_value.return_value = False
        worker = CleanupWorker(db=db)
        assert worker._try_acquire_leader() is False

    def test_try_acquire_leader_exception_returns_false(self):
        """Lines 213-215: exception during advisory lock returns False."""
        db = MagicMock()
        db.fetch_value.side_effect = RuntimeError("connection lost")
        worker = CleanupWorker(db=db)
        assert worker._try_acquire_leader() is False

    def test_release_leader_no_db(self):
        """Lines 219-220: no DB means release is a no-op."""
        worker = CleanupWorker()
        worker._release_leader()  # should not raise

    def test_release_leader_with_db(self):
        """Lines 221-225: calls advisory_unlock on DB."""
        db = MagicMock()
        worker = CleanupWorker(db=db)
        worker._release_leader()
        db.execute.assert_called_once()
        call_args = db.execute.call_args
        assert "pg_advisory_unlock" in call_args[0][0]

    def test_release_leader_suppresses_exception(self):
        """Lines 221-222: exception in release is suppressed."""
        db = MagicMock()
        db.execute.side_effect = RuntimeError("connection gone")
        worker = CleanupWorker(db=db)
        worker._release_leader()  # should not raise


# ===========================================================================
# CleanupWorker — _run loop behavior
# ===========================================================================


class TestCleanupWorkerRunLoop:
    """Tests for the _run loop: leader failure and stop mid-iteration."""

    def test_run_skips_when_leader_not_acquired(self):
        """Lines 231-233: when leader not acquired, waits and continues."""
        db = MagicMock()
        db.fetch_value.return_value = False  # not leader
        settings = _make_retention_settings()
        worker = CleanupWorker(settings=settings, db=db)

        # Add a task to ensure it is NOT executed
        task_func = MagicMock()
        worker._tasks.append(_CleanupTask(name="should_skip", interval_seconds=0, func=task_func))

        wait_timeouts = []

        def capture_wait(timeout=None):
            wait_timeouts.append(timeout)
            worker._stop_event.set()

        worker._stop_event.wait = capture_wait
        worker._run()

        # Task should not have been executed since we were not leader
        task_func.assert_not_called()
        # Wait should have been called with the loop interval
        assert len(wait_timeouts) == 1
        assert wait_timeouts[0] == settings.retention.cleanup_loop_interval_seconds

    def test_run_breaks_on_stop_during_tasks(self):
        """Line 239: stop_event.is_set() during task iteration breaks loop."""
        worker = CleanupWorker()

        call_order = []

        def first_task():
            call_order.append("first")
            worker._stop_event.set()  # set stop during first task

        def second_task():
            call_order.append("second")

        worker._tasks.append(_CleanupTask(name="first", interval_seconds=0, func=first_task))
        worker._tasks.append(_CleanupTask(name="second", interval_seconds=0, func=second_task))

        # Need to handle the final wait call
        original_wait = worker._stop_event.wait
        worker._stop_event.wait = lambda timeout=None: None
        worker._run()
        worker._stop_event.wait = original_wait

        assert "first" in call_order
        assert "second" not in call_order

    def test_start_returns_if_already_alive(self):
        """Line 178-179: start() returns if thread is already alive."""
        worker = CleanupWorker()
        # Add a dummy task so start() doesn't bail for empty tasks
        worker._tasks.append(_CleanupTask(name="dummy", interval_seconds=999, func=lambda: None))

        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        worker._thread = mock_thread

        worker.start()
        # The existing thread should remain; no new thread started
        assert worker._thread is mock_thread


# ===========================================================================
# CleanupWorker — static task methods
# ===========================================================================


class TestCleanupWorkerStaticMethods:
    """Tests for the static task implementation methods."""

    def test_stale_processing_recovery_transitions_orders(self):
        """Lines 308-327: finds stale orders and transitions them."""
        order_repo = MagicMock()
        mock_order_1 = MagicMock()
        mock_order_1.id = uuid.uuid4()
        mock_order_2 = MagicMock()
        mock_order_2.id = uuid.uuid4()
        order_repo.find_stale_processing.return_value = [mock_order_1, mock_order_2]

        CleanupWorker._stale_processing_recovery(order_repo, 600)

        order_repo.find_stale_processing.assert_called_once_with(600)
        assert order_repo.transition_status.call_count == 2

    def test_stale_processing_recovery_no_stale_orders(self):
        """Lines 308-327: no stale orders means no transitions."""
        order_repo = MagicMock()
        order_repo.find_stale_processing.return_value = []

        CleanupWorker._stale_processing_recovery(order_repo, 600)

        order_repo.find_stale_processing.assert_called_once_with(600)
        order_repo.transition_status.assert_not_called()

    def test_audit_retention_deletes_old_entries(self):
        """Lines 336-342: deletes audit entries older than max_age_days."""
        db = MagicMock()
        db.execute.return_value = 42

        CleanupWorker._audit_retention(db, 90)

        db.execute.assert_called_once()
        call_args = db.execute.call_args
        assert "DELETE FROM admin.audit_log" in call_args[0][0]
        # Check that the cutoff date is approximately correct
        cutoff = call_args[0][1][0]
        expected = datetime.now(UTC) - timedelta(days=90)
        assert abs((cutoff - expected).total_seconds()) < 5

    def test_audit_retention_nothing_deleted(self):
        """Lines 336-342: zero deleted rows, no log output."""
        db = MagicMock()
        db.execute.return_value = 0

        CleanupWorker._audit_retention(db, 365)
        db.execute.assert_called_once()

    def test_rate_limit_gc_deletes_entries(self):
        """Lines 349-351: calls limiter.gc() and logs when deleted > 0."""
        limiter = MagicMock()
        limiter.gc.return_value = 15

        CleanupWorker._rate_limit_gc(limiter)

        limiter.gc.assert_called_once()

    def test_rate_limit_gc_nothing_deleted(self):
        """Lines 349-351: limiter.gc() returns 0, no log."""
        limiter = MagicMock()
        limiter.gc.return_value = 0

        CleanupWorker._rate_limit_gc(limiter)
        limiter.gc.assert_called_once()

    def test_authz_retention(self):
        """Data retention: authz cleanup."""
        db = MagicMock()
        db.execute.return_value = 5
        CleanupWorker._authz_retention(db, 90)
        call_args = db.execute.call_args
        assert "authorizations" in call_args[0][0]

    def test_challenge_retention(self):
        """Data retention: challenge cleanup."""
        db = MagicMock()
        db.execute.return_value = 3
        CleanupWorker._challenge_retention(db, 30)
        call_args = db.execute.call_args
        assert "challenges" in call_args[0][0]

    def test_order_retention(self):
        """Data retention: order cleanup."""
        db = MagicMock()
        db.execute.return_value = 10
        CleanupWorker._order_retention(db, 60)
        call_args = db.execute.call_args
        assert "orders" in call_args[0][0]

    def test_notice_retention(self):
        """Data retention: notice cleanup."""
        db = MagicMock()
        db.execute.return_value = 7
        CleanupWorker._notice_retention(db, 180)
        call_args = db.execute.call_args
        assert "certificate_expiration_notices" in call_args[0][0]


# ===========================================================================
# ChallengeWorker — leader election
# ===========================================================================


class TestChallengeWorkerLeaderElection:
    """Leader election for ChallengeWorker."""

    def test_try_acquire_no_db_returns_true(self):
        """Lines 99-100: no DB means always leader."""
        worker = ChallengeWorker(
            challenge_service=MagicMock(),
            challenge_repo=MagicMock(),
            authz_repo=MagicMock(),
            account_repo=MagicMock(),
        )
        assert worker._try_acquire_leader() is True

    def test_try_acquire_with_db_success(self):
        """Lines 101-107: fetch_value returns True -> leader."""
        db = MagicMock()
        db.fetch_value.return_value = True
        worker = ChallengeWorker(
            challenge_service=MagicMock(),
            challenge_repo=MagicMock(),
            authz_repo=MagicMock(),
            account_repo=MagicMock(),
            db=db,
        )
        assert worker._try_acquire_leader() is True

    def test_try_acquire_with_db_false(self):
        """Lines 101-107: fetch_value returns False -> not leader."""
        db = MagicMock()
        db.fetch_value.return_value = False
        worker = ChallengeWorker(
            challenge_service=MagicMock(),
            challenge_repo=MagicMock(),
            authz_repo=MagicMock(),
            account_repo=MagicMock(),
            db=db,
        )
        assert worker._try_acquire_leader() is False

    def test_try_acquire_exception_returns_false(self):
        """Lines 108-110: exception returns False."""
        db = MagicMock()
        db.fetch_value.side_effect = RuntimeError("gone")
        worker = ChallengeWorker(
            challenge_service=MagicMock(),
            challenge_repo=MagicMock(),
            authz_repo=MagicMock(),
            account_repo=MagicMock(),
            db=db,
        )
        assert worker._try_acquire_leader() is False

    def test_release_leader_no_db(self):
        """Lines 114-115: no DB -> no-op."""
        worker = ChallengeWorker(
            challenge_service=MagicMock(),
            challenge_repo=MagicMock(),
            authz_repo=MagicMock(),
            account_repo=MagicMock(),
        )
        worker._release_leader()

    def test_release_leader_with_db(self):
        """Lines 116-119: calls advisory_unlock."""
        db = MagicMock()
        worker = ChallengeWorker(
            challenge_service=MagicMock(),
            challenge_repo=MagicMock(),
            authz_repo=MagicMock(),
            account_repo=MagicMock(),
            db=db,
        )
        worker._release_leader()
        db.execute.assert_called_once()
        assert "pg_advisory_unlock" in db.execute.call_args[0][0]

    def test_release_leader_suppresses_exception(self):
        """Lines 116-117: exception during release is suppressed."""
        db = MagicMock()
        db.execute.side_effect = RuntimeError("oops")
        worker = ChallengeWorker(
            challenge_service=MagicMock(),
            challenge_repo=MagicMock(),
            authz_repo=MagicMock(),
            account_repo=MagicMock(),
            db=db,
        )
        worker._release_leader()  # should not raise


# ===========================================================================
# ChallengeWorker — _run loop
# ===========================================================================


class TestChallengeWorkerRunLoop:
    """Tests for the _run loop when leader not acquired."""

    def test_run_skips_poll_when_not_leader(self):
        """Lines 125-127: when not leader, waits and continues."""
        db = MagicMock()
        db.fetch_value.return_value = False  # not leader
        worker = ChallengeWorker(
            challenge_service=MagicMock(),
            challenge_repo=MagicMock(),
            authz_repo=MagicMock(),
            account_repo=MagicMock(),
            poll_seconds=10,
            db=db,
        )
        worker._poll = MagicMock()

        wait_timeouts = []

        def capture_wait(timeout=None):
            wait_timeouts.append(timeout)
            worker._stop_event.set()

        worker._stop_event.wait = capture_wait
        worker._run()

        worker._poll.assert_not_called()
        assert wait_timeouts == [10]


# ===========================================================================
# ChallengeWorker — _poll internals
# ===========================================================================


class TestChallengeWorkerPoll:
    """Tests for _poll's challenge iteration logic."""

    def test_poll_logs_released_stale_locks(self):
        """Line 164: logs when released > 0."""
        challenge_repo = MagicMock()
        challenge_repo.release_stale_locks.return_value = 3
        challenge_repo.find_by.return_value = []

        worker = ChallengeWorker(
            challenge_service=MagicMock(),
            challenge_repo=challenge_repo,
            authz_repo=MagicMock(),
            account_repo=MagicMock(),
        )
        worker._poll()
        challenge_repo.release_stale_locks.assert_called_once()

    def test_poll_skips_non_pending_challenges(self):
        """Line 180-181: challenges not PENDING are skipped."""
        c = _make_challenge(status="valid", retry_count=1)
        challenge_repo = MagicMock()
        challenge_repo.release_stale_locks.return_value = 0
        challenge_repo.find_by.return_value = [c]

        service = MagicMock()
        worker = ChallengeWorker(
            challenge_service=service,
            challenge_repo=challenge_repo,
            authz_repo=MagicMock(),
            account_repo=MagicMock(),
        )
        worker._poll()
        service.process_pending.assert_not_called()

    def test_poll_skips_zero_retry_count(self):
        """Lines 182-183: challenges with retry_count < 1 are skipped."""
        c = _make_challenge(status="pending", retry_count=0)
        challenge_repo = MagicMock()
        challenge_repo.release_stale_locks.return_value = 0
        challenge_repo.find_by.return_value = [c]

        service = MagicMock()
        worker = ChallengeWorker(
            challenge_service=service,
            challenge_repo=challenge_repo,
            authz_repo=MagicMock(),
            account_repo=MagicMock(),
        )
        worker._poll()
        service.process_pending.assert_not_called()

    def test_poll_skips_challenge_in_backoff_window(self):
        """Lines 185-186: next_retry_at in the future is skipped."""
        future = datetime.now(UTC) + timedelta(hours=1)
        c = _make_challenge(status="pending", retry_count=2, next_retry_at=future)
        challenge_repo = MagicMock()
        challenge_repo.release_stale_locks.return_value = 0
        challenge_repo.find_by.return_value = [c]

        service = MagicMock()
        worker = ChallengeWorker(
            challenge_service=service,
            challenge_repo=challenge_repo,
            authz_repo=MagicMock(),
            account_repo=MagicMock(),
        )
        worker._poll()
        service.process_pending.assert_not_called()

    def test_poll_skips_if_authz_not_found(self):
        """Lines 190-191: authz lookup returns None, challenge skipped."""
        c = _make_challenge(status="pending", retry_count=1, next_retry_at=None)
        challenge_repo = MagicMock()
        challenge_repo.release_stale_locks.return_value = 0
        challenge_repo.find_by.return_value = [c]

        authz_repo = MagicMock()
        authz_repo.find_by_id.return_value = None

        service = MagicMock()
        worker = ChallengeWorker(
            challenge_service=service,
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            account_repo=MagicMock(),
        )
        worker._poll()
        service.process_pending.assert_not_called()

    def test_poll_skips_if_account_not_found(self):
        """Lines 193-195: account lookup returns None, challenge skipped."""
        c = _make_challenge(status="pending", retry_count=1, next_retry_at=None)
        challenge_repo = MagicMock()
        challenge_repo.release_stale_locks.return_value = 0
        challenge_repo.find_by.return_value = [c]

        authz = MagicMock()
        authz.account_id = uuid.uuid4()
        authz_repo = MagicMock()
        authz_repo.find_by_id.return_value = authz

        account_repo = MagicMock()
        account_repo.find_by_id.return_value = None

        service = MagicMock()
        worker = ChallengeWorker(
            challenge_service=service,
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            account_repo=account_repo,
        )
        worker._poll()
        service.process_pending.assert_not_called()

    def test_poll_claims_and_processes_challenge(self):
        """Lines 204-212: successful claim and process."""
        c = _make_challenge(status="pending", retry_count=1, next_retry_at=None)
        challenge_repo = MagicMock()
        challenge_repo.release_stale_locks.return_value = 0
        challenge_repo.find_by.return_value = [c]
        challenge_repo.claim_for_processing.return_value = c

        authz = MagicMock()
        authz.account_id = uuid.uuid4()
        authz_repo = MagicMock()
        authz_repo.find_by_id.return_value = authz

        account = MagicMock()
        account.jwk = {"kty": "RSA", "n": "test"}
        account_repo = MagicMock()
        account_repo.find_by_id.return_value = account

        service = MagicMock()
        worker = ChallengeWorker(
            challenge_service=service,
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            account_repo=account_repo,
        )
        worker._poll()
        service.process_pending.assert_called_once()

    def test_poll_skips_when_claim_returns_none(self):
        """Lines 207-208: claim_for_processing returns None, skip."""
        c = _make_challenge(status="pending", retry_count=1, next_retry_at=None)
        challenge_repo = MagicMock()
        challenge_repo.release_stale_locks.return_value = 0
        challenge_repo.find_by.return_value = [c]
        challenge_repo.claim_for_processing.return_value = None

        authz = MagicMock()
        authz.account_id = uuid.uuid4()
        authz_repo = MagicMock()
        authz_repo.find_by_id.return_value = authz

        account = MagicMock()
        account.jwk = {"kty": "RSA"}
        account_repo = MagicMock()
        account_repo.find_by_id.return_value = account

        service = MagicMock()
        worker = ChallengeWorker(
            challenge_service=service,
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            account_repo=account_repo,
        )
        worker._poll()
        service.process_pending.assert_not_called()

    def test_poll_handles_process_exception(self):
        """Lines 213-216: exception during process_pending is caught."""
        c = _make_challenge(status="pending", retry_count=1, next_retry_at=None)
        challenge_repo = MagicMock()
        challenge_repo.release_stale_locks.return_value = 0
        challenge_repo.find_by.return_value = [c]
        challenge_repo.claim_for_processing.return_value = c

        authz = MagicMock()
        authz.account_id = uuid.uuid4()
        authz_repo = MagicMock()
        authz_repo.find_by_id.return_value = authz

        account = MagicMock()
        account.jwk = {"kty": "RSA"}
        account_repo = MagicMock()
        account_repo.find_by_id.return_value = account

        service = MagicMock()
        service.process_pending.side_effect = RuntimeError("process failed")

        worker = ChallengeWorker(
            challenge_service=service,
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            account_repo=account_repo,
        )
        # Should not raise
        worker._poll()

    def test_poll_breaks_on_stop_event(self):
        """Line 179: stop_event set during iteration breaks loop."""
        c1 = _make_challenge(status="pending", retry_count=1, next_retry_at=None)
        c2 = _make_challenge(status="pending", retry_count=1, next_retry_at=None)
        challenge_repo = MagicMock()
        challenge_repo.release_stale_locks.return_value = 0
        challenge_repo.find_by.return_value = [c1, c2]
        challenge_repo.claim_for_processing.return_value = MagicMock()

        authz = MagicMock()
        authz.account_id = uuid.uuid4()
        authz_repo = MagicMock()
        authz_repo.find_by_id.return_value = authz

        account = MagicMock()
        account.jwk = {"kty": "RSA"}
        account_repo = MagicMock()
        account_repo.find_by_id.return_value = account

        service = MagicMock()

        # On first call, set the stop event so the second challenge is skipped
        def _stop_on_first_call(*args, **kwargs):
            worker._stop_event.set()

        service.process_pending.side_effect = _stop_on_first_call

        worker = ChallengeWorker(
            challenge_service=service,
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            account_repo=account_repo,
        )
        worker._poll()
        # Only one challenge was processed
        assert service.process_pending.call_count == 1


# ===========================================================================
# ExpirationWorker — start() guard conditions
# ===========================================================================


class TestExpirationWorkerStart:
    """Tests for start() early-return conditions."""

    def test_start_returns_when_disabled(self):
        """Line 63-64: disabled settings means no thread started."""
        settings = _make_notification_settings(enabled=False)
        worker = ExpirationWorker(
            cert_repo=MagicMock(),
            notification_service=MagicMock(),
            settings=settings,
        )
        worker.start()
        assert worker._thread is None

    def test_start_returns_when_no_warning_days(self):
        """Line 63-64: empty warning_days means no thread started."""
        settings = _make_notification_settings(enabled=True, warning_days=[])
        worker = ExpirationWorker(
            cert_repo=MagicMock(),
            notification_service=MagicMock(),
            settings=settings,
        )
        worker.start()
        assert worker._thread is None

    def test_start_returns_when_no_notifier(self):
        """Lines 65-66: notification_service is None means no thread started."""
        settings = _make_notification_settings(enabled=True)
        worker = ExpirationWorker(
            cert_repo=MagicMock(),
            notification_service=None,
            settings=settings,
        )
        worker.start()
        assert worker._thread is None

    def test_start_returns_when_thread_already_alive(self):
        """Lines 67-68: already running thread means start() is a no-op."""
        settings = _make_notification_settings(enabled=True)
        worker = ExpirationWorker(
            cert_repo=MagicMock(),
            notification_service=MagicMock(),
            settings=settings,
        )
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        worker._thread = mock_thread
        worker.start()
        assert worker._thread is mock_thread


# ===========================================================================
# ExpirationWorker — leader election
# ===========================================================================


class TestExpirationWorkerLeaderElection:
    """Leader election for ExpirationWorker."""

    def test_try_acquire_no_db_returns_true(self):
        """Lines 92-93: no DB -> always leader."""
        settings = _make_notification_settings()
        worker = ExpirationWorker(
            cert_repo=MagicMock(),
            notification_service=MagicMock(),
            settings=settings,
        )
        assert worker._try_acquire_leader() is True

    def test_try_acquire_with_db_success(self):
        """Lines 94-100: fetch_value True -> leader."""
        db = MagicMock()
        db.fetch_value.return_value = True
        settings = _make_notification_settings()
        worker = ExpirationWorker(
            cert_repo=MagicMock(),
            notification_service=MagicMock(),
            settings=settings,
            db=db,
        )
        assert worker._try_acquire_leader() is True

    def test_try_acquire_with_db_false(self):
        """Lines 94-100: fetch_value False -> not leader."""
        db = MagicMock()
        db.fetch_value.return_value = False
        settings = _make_notification_settings()
        worker = ExpirationWorker(
            cert_repo=MagicMock(),
            notification_service=MagicMock(),
            settings=settings,
            db=db,
        )
        assert worker._try_acquire_leader() is False

    def test_try_acquire_exception_returns_false(self):
        """Lines 101-103: exception returns False."""
        db = MagicMock()
        db.fetch_value.side_effect = RuntimeError("lost")
        settings = _make_notification_settings()
        worker = ExpirationWorker(
            cert_repo=MagicMock(),
            notification_service=MagicMock(),
            settings=settings,
            db=db,
        )
        assert worker._try_acquire_leader() is False

    def test_release_leader_with_db(self):
        """Lines 109-112: calls advisory_unlock."""
        db = MagicMock()
        settings = _make_notification_settings()
        worker = ExpirationWorker(
            cert_repo=MagicMock(),
            notification_service=MagicMock(),
            settings=settings,
            db=db,
        )
        worker._release_leader()
        db.execute.assert_called_once()
        assert "pg_advisory_unlock" in db.execute.call_args[0][0]


# ===========================================================================
# ExpirationWorker — _run loop
# ===========================================================================


class TestExpirationWorkerRunLoop:
    """Tests for the _run loop when leader not acquired."""

    def test_run_skips_when_not_leader(self):
        """Lines 118-122: when not leader, waits and continues."""
        db = MagicMock()
        db.fetch_value.return_value = False  # not leader
        settings = _make_notification_settings(interval=30)
        worker = ExpirationWorker(
            cert_repo=MagicMock(),
            notification_service=MagicMock(),
            settings=settings,
            db=db,
        )
        worker._check_expirations = MagicMock()

        wait_timeouts = []

        def capture_wait(timeout=None):
            wait_timeouts.append(timeout)
            worker._stop_event.set()

        worker._stop_event.wait = capture_wait
        worker._run()

        worker._check_expirations.assert_not_called()
        assert wait_timeouts == [30]


# ===========================================================================
# ExpirationWorker — _check_expirations
# ===========================================================================


class TestExpirationWorkerCheckExpirations:
    """Tests for _check_expirations internals."""

    def test_check_expirations_returns_on_stop(self):
        """Line 161: if stop_event is set during cert iteration, returns."""
        settings = _make_notification_settings(warning_days=[30])
        cert_repo = MagicMock()
        cert1 = MagicMock()
        cert1.id = uuid.uuid4()
        cert1.account_id = uuid.uuid4()
        cert1.serial_number = "AABB"
        cert1.not_after_cert = datetime.now(UTC) + timedelta(days=20)
        cert_repo.find_expiring.return_value = [cert1]

        notifier = MagicMock()
        worker = ExpirationWorker(
            cert_repo=cert_repo,
            notification_service=notifier,
            settings=settings,
        )
        # Set stop event so _check_expirations returns before sending
        worker._stop_event.set()
        worker._check_expirations()
        notifier.notify.assert_not_called()

    def test_check_expirations_sends_notification_with_metrics(self):
        """Line 182: metrics increment on successful notification."""
        settings = _make_notification_settings(warning_days=[30])
        cert_repo = MagicMock()
        cert1 = MagicMock()
        cert1.id = uuid.uuid4()
        cert1.account_id = uuid.uuid4()
        cert1.serial_number = "CCDD"
        cert1.not_after_cert = datetime.now(UTC) + timedelta(days=20)
        cert_repo.find_expiring.return_value = [cert1]

        notifier = MagicMock()
        metrics = MetricsCollector()
        worker = ExpirationWorker(
            cert_repo=cert_repo,
            notification_service=notifier,
            settings=settings,
            metrics=metrics,
        )
        # _try_claim_notice returns True (no DB)
        worker._check_expirations()
        notifier.notify.assert_called_once()
        assert metrics.get("acmeeh_expiration_warnings_sent_total") == 1

    def test_check_expirations_skips_when_claim_fails(self):
        """Lines 165-166: _try_claim_notice returns False -> skip."""
        settings = _make_notification_settings(warning_days=[7])
        cert_repo = MagicMock()
        cert1 = MagicMock()
        cert1.id = uuid.uuid4()
        cert_repo.find_expiring.return_value = [cert1]

        notifier = MagicMock()
        db = MagicMock()
        # INSERT returns 0 rowcount -> claim fails
        db.execute.return_value = 0

        worker = ExpirationWorker(
            cert_repo=cert_repo,
            notification_service=notifier,
            settings=settings,
            db=db,
        )
        worker._check_expirations()
        notifier.notify.assert_not_called()


# ===========================================================================
# ExpirationWorker — _try_claim_notice
# ===========================================================================


class TestExpirationWorkerTryClaimNotice:
    """Tests for _try_claim_notice."""

    def test_try_claim_no_db_returns_true(self):
        """Lines 191-193: no DB always returns True."""
        settings = _make_notification_settings()
        worker = ExpirationWorker(
            cert_repo=MagicMock(),
            notification_service=MagicMock(),
            settings=settings,
        )
        assert worker._try_claim_notice(uuid.uuid4(), 30) is True

    def test_try_claim_with_db_success(self):
        """Lines 194-201: rowcount == 1 -> True."""
        db = MagicMock()
        db.execute.return_value = 1
        settings = _make_notification_settings()
        worker = ExpirationWorker(
            cert_repo=MagicMock(),
            notification_service=MagicMock(),
            settings=settings,
            db=db,
        )
        assert worker._try_claim_notice(uuid.uuid4(), 30) is True

    def test_try_claim_with_db_conflict(self):
        """Lines 194-201: rowcount == 0 (conflict) -> False."""
        db = MagicMock()
        db.execute.return_value = 0
        settings = _make_notification_settings()
        worker = ExpirationWorker(
            cert_repo=MagicMock(),
            notification_service=MagicMock(),
            settings=settings,
            db=db,
        )
        assert worker._try_claim_notice(uuid.uuid4(), 7) is False

    def test_try_claim_exception_returns_false(self):
        """Lines 202-208: exception during INSERT returns False."""
        db = MagicMock()
        db.execute.side_effect = RuntimeError("db error")
        settings = _make_notification_settings()
        worker = ExpirationWorker(
            cert_repo=MagicMock(),
            notification_service=MagicMock(),
            settings=settings,
            db=db,
        )
        assert worker._try_claim_notice(uuid.uuid4(), 30) is False
