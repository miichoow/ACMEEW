"""Tests for the background challenge validation worker."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest

from acmeeh.core.types import AccountStatus, AuthorizationStatus, ChallengeStatus, ChallengeType
from acmeeh.models.challenge import Challenge
from acmeeh.services.workers import ChallengeWorker

# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FakeAuthz:
    id: UUID
    account_id: UUID
    status: AuthorizationStatus = AuthorizationStatus.PENDING


@dataclass(frozen=True)
class FakeAccount:
    id: UUID
    jwk: dict
    jwk_thumbprint: str = "test-thumbprint"
    status: AccountStatus = AccountStatus.VALID
    tos_agreed: bool = True


class StubChallengeRepo:
    def __init__(self, challenges: list[Challenge] | None = None):
        self._challenges = {c.id: c for c in (challenges or [])}
        self.release_stale_locks_count = 0

    def release_stale_locks(self, threshold: datetime) -> int:
        self.release_stale_locks_count += 1
        return 0

    def find_by(self, criteria: dict) -> list:
        return list(self._challenges.values())

    def claim_for_processing(self, challenge_id, worker_id):
        return self._challenges.get(challenge_id)


class StubAuthzRepo:
    def __init__(self, authzs: dict[UUID, FakeAuthz] | None = None):
        self._data = authzs or {}

    def find_by_id(self, authz_id: UUID):
        return self._data.get(authz_id)


class StubAccountRepo:
    def __init__(self, accounts: dict[UUID, FakeAccount] | None = None):
        self._data = accounts or {}

    def find_by_id(self, account_id: UUID):
        return self._data.get(account_id)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_service():
    service = MagicMock()
    service.process_pending = MagicMock()
    return service


@pytest.fixture
def challenge_repo():
    return StubChallengeRepo()


@pytest.fixture
def authz_repo():
    return StubAuthzRepo()


@pytest.fixture
def account_repo():
    return StubAccountRepo()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestWorkerStartStop:
    """Worker starts and stops cleanly."""

    def test_start_creates_thread(self, mock_service, challenge_repo, authz_repo, account_repo):
        worker = ChallengeWorker(
            challenge_service=mock_service,
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            account_repo=account_repo,
            poll_seconds=1,
        )
        worker.start()
        assert worker._thread is not None
        assert worker._thread.is_alive()
        worker.stop()
        assert not worker._thread.is_alive()

    def test_start_is_idempotent(self, mock_service, challenge_repo, authz_repo, account_repo):
        worker = ChallengeWorker(
            challenge_service=mock_service,
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            account_repo=account_repo,
            poll_seconds=1,
        )
        worker.start()
        first_thread = worker._thread
        worker.start()  # Second start should be a no-op
        assert worker._thread is first_thread
        worker.stop()

    def test_stop_without_start(self, mock_service, challenge_repo, authz_repo, account_repo):
        worker = ChallengeWorker(
            challenge_service=mock_service,
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            account_repo=account_repo,
        )
        # Should not raise
        worker.stop()


class TestShutdownEvent:
    """Worker respects shutdown event."""

    def test_stop_event_terminates_loop(
        self, mock_service, challenge_repo, authz_repo, account_repo
    ):
        worker = ChallengeWorker(
            challenge_service=mock_service,
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            account_repo=account_repo,
            poll_seconds=60,  # Long poll so we know it exits via stop_event
        )
        worker.start()
        time.sleep(0.1)  # Let the thread start its first iteration
        worker.stop()
        # Thread should have exited
        assert not worker._thread.is_alive()


class TestPollInterval:
    """Poll interval is configurable."""

    def test_custom_poll_interval(self, mock_service, challenge_repo, authz_repo, account_repo):
        worker = ChallengeWorker(
            challenge_service=mock_service,
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            account_repo=account_repo,
            poll_seconds=2,
            stale_seconds=120,
        )
        assert worker._poll_seconds == 2
        assert worker._stale_seconds == 120

    def test_default_poll_interval(self, mock_service, challenge_repo, authz_repo, account_repo):
        worker = ChallengeWorker(
            challenge_service=mock_service,
            challenge_repo=challenge_repo,
            authz_repo=authz_repo,
            account_repo=account_repo,
        )
        assert worker._poll_seconds == 10
        assert worker._stale_seconds == 300


class TestExceptionHandling:
    """Worker handles exceptions gracefully without crashing."""

    def test_poll_exception_does_not_crash_worker(self, mock_service, authz_repo, account_repo):
        # Create a challenge repo that raises on find_by
        failing_repo = StubChallengeRepo()
        failing_repo.release_stale_locks = MagicMock(side_effect=RuntimeError("DB error"))

        worker = ChallengeWorker(
            challenge_service=mock_service,
            challenge_repo=failing_repo,
            authz_repo=authz_repo,
            account_repo=account_repo,
            poll_seconds=1,
        )
        worker.start()
        # Let the worker attempt a poll (which will fail)
        time.sleep(0.5)
        # Worker should still be alive despite the exception
        assert worker._thread.is_alive()
        worker.stop()

    def test_process_pending_exception_handled(self, mock_service, authz_repo, account_repo):
        account_id = uuid4()
        authz_id = uuid4()
        challenge = Challenge(
            id=uuid4(),
            authorization_id=authz_id,
            type=ChallengeType.HTTP_01,
            token="test-token",
            status=ChallengeStatus.PENDING,
            retry_count=1,
        )

        authz = FakeAuthz(id=authz_id, account_id=account_id)
        account = FakeAccount(id=account_id, jwk={"kty": "EC"})

        challenge_repo = StubChallengeRepo([challenge])
        authz_repo_with_data = StubAuthzRepo({authz_id: authz})
        account_repo_with_data = StubAccountRepo({account_id: account})

        mock_service.process_pending.side_effect = RuntimeError("Validation error")

        worker = ChallengeWorker(
            challenge_service=mock_service,
            challenge_repo=challenge_repo,
            authz_repo=authz_repo_with_data,
            account_repo=account_repo_with_data,
            poll_seconds=1,
        )
        worker.start()
        time.sleep(0.5)
        # Worker should still be alive
        assert worker._thread.is_alive()
        worker.stop()
