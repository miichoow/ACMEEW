"""Graceful shutdown coordinator.

Tracks in-flight operations and ensures they complete (up to a timeout)
before the process exits.

Usage::

    from acmeeh.app.shutdown import ShutdownCoordinator

    coordinator = ShutdownCoordinator(graceful_timeout=30)

    with coordinator.track("crl_rebuild"):
        rebuild_crl()

    coordinator.initiate()  # waits for tracked ops to finish
"""

from __future__ import annotations

import logging
import signal
import threading
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Generator

log = logging.getLogger(__name__)


class ShutdownCoordinator:
    """Coordinates graceful shutdown by tracking in-flight operations.

    Parameters
    ----------
    graceful_timeout:
        Maximum seconds to wait for in-flight operations during shutdown.

    """

    def __init__(self, graceful_timeout: int = 30) -> None:
        self._graceful_timeout = graceful_timeout
        self._shutdown_flag = threading.Event()
        self._reload_flag = threading.Event()
        self._maintenance_flag = threading.Event()
        self._in_flight = 0
        self._lock = threading.Lock()
        self._done = threading.Condition(self._lock)

    @property
    def is_shutting_down(self) -> bool:
        """True once :meth:`initiate` has been called."""
        return self._shutdown_flag.is_set()

    @property
    def in_flight_count(self) -> int:
        """Number of currently tracked operations."""
        with self._lock:
            return self._in_flight

    @contextmanager
    def track(self, name: str) -> Generator[None, None, None]:
        """Context manager to track an in-flight operation.

        If shutdown has already been initiated, the operation is still
        allowed to proceed (we don't want to break existing work), but
        a warning is logged.
        """
        if self._shutdown_flag.is_set():
            log.warning("Operation '%s' starting during shutdown", name)

        with self._lock:
            self._in_flight += 1

        try:
            yield
        finally:
            with self._done:
                self._in_flight -= 1
                if self._in_flight == 0:
                    self._done.notify_all()

    def initiate(self) -> None:
        """Begin graceful shutdown.

        Sets the shutdown flag and waits up to ``graceful_timeout``
        seconds for in-flight operations to complete.
        """
        if self._shutdown_flag.is_set():
            return

        self._shutdown_flag.set()
        log.info("Graceful shutdown initiated")

        with self._done:
            deadline = time.monotonic() + self._graceful_timeout
            while self._in_flight > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    log.warning(
                        "Shutdown timeout expired with %d operations in flight",
                        self._in_flight,
                    )
                    break
                self._done.wait(timeout=remaining)

        if self._in_flight == 0:
            log.info("All in-flight operations completed")

    @property
    def maintenance_mode(self) -> bool:
        """True when the server is in maintenance mode.

        In maintenance mode, new order and pre-authorization creation
        is blocked (503), but existing order finalization, challenge
        validation, and certificate downloads continue to work.
        """
        return self._maintenance_flag.is_set()

    def set_maintenance(self, enabled: bool) -> None:
        """Enable or disable maintenance mode."""
        if enabled:
            self._maintenance_flag.set()
            log.info("Maintenance mode ENABLED — new orders blocked")
        else:
            self._maintenance_flag.clear()
            log.info("Maintenance mode DISABLED — new orders allowed")

    @property
    def reload_requested(self) -> bool:
        """True if a SIGHUP was received and reload has not been consumed."""
        return self._reload_flag.is_set()

    def consume_reload(self) -> None:
        """Clear the reload flag after handling it."""
        self._reload_flag.clear()

    def register_signals(self) -> None:
        """Register SIGTERM and SIGINT handlers to initiate shutdown.

        Must be called from the main thread.
        """
        try:
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal.signal(signal.SIGINT, self._signal_handler)
        except (ValueError, OSError):
            # Not in main thread or signals not supported (Windows service)
            log.debug("Could not register signal handlers (not main thread)")

    def drain_processing_challenges(self, challenge_repo: Any) -> int:
        """Move PROCESSING challenges back to PENDING for retry on healthy instances.

        Called during graceful shutdown to avoid partial state visible to clients.
        Returns the number of challenges drained.
        """
        if challenge_repo is None:
            return 0
        try:
            count = challenge_repo.drain_processing()
            if count > 0:
                log.info("Drained %d PROCESSING challenges back to PENDING", count)
            return count
        except Exception:
            log.exception("Failed to drain processing challenges during shutdown")
            return 0

    def register_reload_signal(self) -> None:
        """Register SIGHUP handler for config hot-reload.

        Must be called from the main thread. On Windows, SIGHUP is not
        available — this is a no-op.
        """
        if not hasattr(signal, "SIGHUP"):
            log.debug("SIGHUP not available on this platform (Windows?)")
            return
        try:
            signal.signal(signal.SIGHUP, self._reload_handler)
            log.info("SIGHUP handler registered for config hot-reload")
        except (ValueError, OSError):
            log.debug("Could not register SIGHUP handler (not main thread)")

    def _signal_handler(self, signum: int, frame) -> None:
        sig_name = signal.Signals(signum).name
        log.info("Received %s, initiating graceful shutdown", sig_name)
        # Run in a thread to avoid blocking the signal handler
        threading.Thread(
            target=self.initiate,
            name="shutdown-coordinator",
            daemon=True,
        ).start()

    def _reload_handler(self, signum: int, frame) -> None:
        log.info("Received SIGHUP, flagging config reload")
        self._reload_flag.set()
