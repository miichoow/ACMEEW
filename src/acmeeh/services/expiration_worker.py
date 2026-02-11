"""Certificate expiration warning worker.

Daemon thread that periodically checks for certificates nearing expiry
and sends notification warnings.  Deduplicates via a
``certificate_expiration_notices`` table so each (cert, threshold)
pair is only notified once.

Usage::

    worker = ExpirationWorker(cert_repo, notification_service, settings, db)
    worker.start()
    ...
    worker.stop()
"""

from __future__ import annotations

import contextlib
import logging
import threading
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pypgkit import Database

    from acmeeh.config.settings import NotificationSettings
    from acmeeh.repositories.certificate import CertificateRepository
    from acmeeh.services.notification import NotificationService

log = logging.getLogger(__name__)


class ExpirationWorker:
    """Daemon thread that sends certificate expiration warnings.

    When a database is provided, uses ``pg_try_advisory_lock`` to ensure
    only one instance across the cluster sends expiration notifications.
    """

    # Advisory lock ID for leader election (arbitrary but stable)
    _ADVISORY_LOCK_ID = 712_002  # stable lock ID for expiration worker

    def __init__(
        self,
        cert_repo: CertificateRepository,
        notification_service: NotificationService | None,
        settings: NotificationSettings,
        db: Database | None = None,
        metrics=None,
    ) -> None:
        self._certs = cert_repo
        self._notifier = notification_service
        self._settings = settings
        self._db = db
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._metrics = metrics
        self._consecutive_failures = 0

    def start(self) -> None:
        """Start the background worker thread."""
        if not self._settings.enabled or not self._settings.expiration_warning_days:
            return
        if self._notifier is None:
            return
        if self._thread is not None and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="expiration-worker",
            daemon=True,
        )
        self._thread.start()
        log.info(
            "Expiration worker started (thresholds=%s, interval=%ds)",
            list(self._settings.expiration_warning_days),
            self._settings.expiration_check_interval_seconds,
        )

    def stop(self) -> None:
        """Signal the worker to stop and wait for it."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self._settings.expiration_check_interval_seconds + 5)
            log.info("Expiration worker stopped")

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
            # Leader election: only one instance sends notifications
            if not self._try_acquire_leader():
                self._stop_event.wait(
                    timeout=self._settings.expiration_check_interval_seconds,
                )
                continue

            try:
                self._check_expirations()
                self._consecutive_failures = 0
            except Exception:
                self._consecutive_failures += 1
                log.exception(
                    "Expiration worker check failed (consecutive: %d)",
                    self._consecutive_failures,
                )
                if self._metrics:
                    self._metrics.increment("acmeeh_expiration_worker_errors_total")
                # Exponential backoff, capped at 8x the interval
                backoff = min(
                    self._settings.expiration_check_interval_seconds
                    * (2**self._consecutive_failures),
                    self._settings.expiration_check_interval_seconds * 8,
                )
                self._stop_event.wait(timeout=backoff)
                self._release_leader()
                continue
            finally:
                self._release_leader()
            self._stop_event.wait(
                timeout=self._settings.expiration_check_interval_seconds,
            )

    def _check_expirations(self) -> None:
        """Check each warning threshold and send notifications."""
        from acmeeh.core.types import NotificationType

        now = datetime.now(UTC)

        for warning_days in self._settings.expiration_warning_days:
            cutoff = now + timedelta(days=warning_days)
            expiring = self._certs.find_expiring(cutoff)

            for cert in expiring:
                if self._stop_event.is_set():
                    return

                # Atomically claim this notification via INSERT.
                # If another instance already inserted, we skip.
                if not self._try_claim_notice(cert.id, warning_days):
                    continue

                # Send notification (we won the race)
                if self._notifier is not None:
                    self._notifier.notify(
                        NotificationType.EXPIRATION_WARNING,
                        cert.account_id,
                        {
                            "certificate_id": str(cert.id),
                            "serial_number": cert.serial_number,
                            "not_after": str(cert.not_after_cert),
                            "warning_days": warning_days,
                        },
                    )

                if self._metrics:
                    self._metrics.increment("acmeeh_expiration_warnings_sent_total")

    def _try_claim_notice(self, cert_id, warning_days: int) -> bool:
        """Atomically claim this notification via INSERT ON CONFLICT DO NOTHING.

        Returns True if this instance won the insert (rowcount == 1),
        meaning we should send the notification.  Returns False if another
        instance already recorded it (conflict, rowcount == 0).
        """
        if self._db is None:
            # No DB — cannot deduplicate, allow notification
            return True
        try:
            rowcount = self._db.execute(
                "INSERT INTO certificate_expiration_notices "
                "(certificate_id, warning_days) VALUES (%s, %s) "
                "ON CONFLICT DO NOTHING",
                (cert_id, warning_days),
            )
            return rowcount == 1
        except Exception:
            log.exception(
                "Failed to claim expiration notice for cert %s (%d days)",
                cert_id,
                warning_days,
            )
            # On error, skip to avoid duplicates
            return False
