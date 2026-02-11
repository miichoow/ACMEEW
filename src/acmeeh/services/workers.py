"""Background challenge validation worker.

Polls for stale PROCESSING challenges and re-processes them.
Runs as a daemon thread started during application startup.
"""

from __future__ import annotations

import contextlib
import logging
import threading
from datetime import UTC
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from acmeeh.repositories.account import AccountRepository
    from acmeeh.repositories.authorization import AuthorizationRepository
    from acmeeh.repositories.challenge import ChallengeRepository
    from acmeeh.services.challenge import ChallengeService

log = logging.getLogger(__name__)


class ChallengeWorker:
    """Daemon thread that processes stale PROCESSING challenges.

    When a database is provided, uses ``pg_try_advisory_lock`` to ensure
    only one instance across the cluster processes stale challenges.

    Parameters
    ----------
    challenge_service:
        The challenge service for processing.
    challenge_repo:
        Challenge repository for finding stale challenges.
    authz_repo:
        Authorization repository for looking up authz -> account.
    account_repo:
        Account repository for looking up account -> JWK.
    poll_seconds:
        How often to poll for stale challenges (default 10).
    stale_seconds:
        Max age in seconds before a PROCESSING challenge is considered stale (default 300).

    """

    # Advisory lock ID for leader election (arbitrary but stable)
    _ADVISORY_LOCK_ID = 712_003  # stable lock ID for challenge worker

    def __init__(
        self,
        challenge_service: ChallengeService,
        challenge_repo: ChallengeRepository,
        authz_repo: AuthorizationRepository,
        account_repo: AccountRepository,
        poll_seconds: int = 10,
        stale_seconds: int = 300,
        metrics=None,
        db=None,
    ) -> None:
        self._service = challenge_service
        self._challenges = challenge_repo
        self._authz = authz_repo
        self._accounts = account_repo
        self._poll_seconds = poll_seconds
        self._stale_seconds = stale_seconds
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._metrics = metrics
        self._consecutive_failures = 0
        self._db = db

    def start(self) -> None:
        """Start the background worker thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="challenge-worker",
            daemon=True,
        )
        self._thread.start()
        log.info(
            "Challenge worker started (poll=%ds, stale=%ds)",
            self._poll_seconds,
            self._stale_seconds,
        )

    def stop(self) -> None:
        """Signal the worker to stop and wait for it."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self._poll_seconds + 5)
            log.info("Challenge worker stopped")

    def _try_acquire_leader(self) -> bool:
        """Try to acquire the advisory lock for leader election."""
        if self._db is None:
            return True
        try:
            return bool(
                self._db.fetch_value(
                    "SELECT pg_try_advisory_lock(%s)",
                    (self._ADVISORY_LOCK_ID,),
                ),
            )
        except Exception:
            log.debug("Advisory lock check failed, skipping this cycle")
            return False

    def _release_leader(self) -> None:
        """Release the advisory lock."""
        if self._db is None:
            return
        with contextlib.suppress(Exception):
            self._db.execute(
                "SELECT pg_advisory_unlock(%s)",
                (self._ADVISORY_LOCK_ID,),
            )

    def _run(self) -> None:
        """Main worker loop."""
        while not self._stop_event.is_set():
            # Leader election: only one instance processes stale challenges
            if not self._try_acquire_leader():
                self._stop_event.wait(timeout=self._poll_seconds)
                continue

            try:
                self._poll()
                self._consecutive_failures = 0
                if self._metrics:
                    self._metrics.increment("acmeeh_challenge_worker_polls_total")
            except Exception:
                self._consecutive_failures += 1
                log.exception(
                    "Challenge worker poll error (consecutive failures: %d)",
                    self._consecutive_failures,
                )
                if self._metrics:
                    self._metrics.increment("acmeeh_challenge_worker_errors_total")
                # Exponential backoff: poll_seconds * 2^failures, capped at 300s
                backoff = min(
                    self._poll_seconds * (2**self._consecutive_failures),
                    300,
                )
                self._stop_event.wait(timeout=backoff)
                self._release_leader()
                continue
            finally:
                self._release_leader()
            self._stop_event.wait(timeout=self._poll_seconds)

    def _poll(self) -> None:
        """Find and process stale challenges."""
        import uuid as _uuid
        from datetime import datetime, timedelta

        _request_id = f"bg-worker-{_uuid.uuid4().hex[:12]}"

        threshold = datetime.now(UTC) - timedelta(seconds=self._stale_seconds)
        released = self._challenges.release_stale_locks(threshold)
        if released > 0:
            log.info(
                "Released %d stale challenge locks", released, extra={"request_id": _request_id}
            )

        # Find challenges that were just released back to pending
        # and process them by looking up their authz and account
        # Find pending challenges that have been retried (retry_count > 0)
        # These are the ones that were released from stale locks
        # Respect next_retry_at for exponential backoff scheduling
        from uuid import uuid4

        from acmeeh.core.types import ChallengeStatus

        now_utc = datetime.now(UTC)

        all_challenges = self._challenges.find_by({})
        for challenge in all_challenges:
            if self._stop_event.is_set():
                break
            if challenge.status != ChallengeStatus.PENDING:
                continue
            if challenge.retry_count < 1:
                continue
            # Skip challenges whose backoff window hasn't elapsed yet
            if challenge.next_retry_at is not None and challenge.next_retry_at > now_utc:
                continue

            # Look up authorization -> account -> JWK
            authz = self._authz.find_by_id(challenge.authorization_id)
            if authz is None:
                continue

            account = self._accounts.find_by_id(authz.account_id)
            if account is None:
                continue

            worker_id = f"bg-{uuid4().hex[:8]}"
            log.debug(
                "Processing stale challenge %s",
                challenge.id,
                extra={"request_id": _request_id, "worker_id": worker_id},
            )
            try:
                claimed = self._challenges.claim_for_processing(
                    challenge.id,
                    worker_id,
                )
                if claimed is None:
                    continue

                self._service.process_pending(
                    challenge.id,
                    worker_id,
                    account.jwk,
                )
            except Exception:
                log.exception(
                    "Failed to process challenge %s",
                    challenge.id,
                )
