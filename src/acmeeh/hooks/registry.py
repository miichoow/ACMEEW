"""Hook registry — loads, manages, and dispatches lifecycle hooks.

Loads :class:`Hook` subclasses from configuration at startup, manages
a :class:`~concurrent.futures.ThreadPoolExecutor` for async dispatch,
and provides the central :meth:`dispatch` method used by all services.

Production hardening:
- Fire-and-forget dispatch (never blocks the caller)
- Context isolation via ``copy.deepcopy`` + shallow copy per hook
- Structured logging with hook_name, event, duration_ms
- Thread-safe dispatch/error counters
- Shutdown guard via ``threading.Event``
- Fail-loud hook loading (broken hook → app refuses to start)
- class_path regex validation before ``importlib``
- ``validate_config()`` called before instantiation

Usage::

    from acmeeh.hooks.registry import HookRegistry

    registry = HookRegistry(settings.hooks)
    registry.dispatch("certificate.issuance", {"serial_number": "..."})
"""

from __future__ import annotations

import copy
import importlib
import logging
import re
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from acmeeh.hooks.base import Hook
from acmeeh.hooks.events import EVENT_METHOD_MAP, KNOWN_EVENTS

if TYPE_CHECKING:
    from acmeeh.config.settings import HookEntrySettings, HookSettings

log = logging.getLogger(__name__)

_CLASS_PATH_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)+$")


@dataclass
class _LoadedHook:
    """Internal wrapper for a loaded hook instance."""

    instance: Hook
    entry: HookEntrySettings
    subscribed_events: frozenset = field(default_factory=frozenset)


class HookRegistry:
    """Registry of loaded hooks with fire-and-forget dispatch.

    Parameters
    ----------
    settings:
        The ``hooks`` section from :class:`AcmeehSettings`.

    """

    def __init__(self, settings: HookSettings) -> None:
        self._settings = settings
        self._hooks: list[_LoadedHook] = []
        self._executor: ThreadPoolExecutor | None = None
        self._shutdown_event = threading.Event()
        self._dispatch_count: int = 0
        self._error_count: int = 0
        self._lock = threading.Lock()
        self._load()

    # -- metrics properties ------------------------------------------------

    @property
    def dispatch_count(self) -> int:
        """Total number of hook dispatches completed (success + error)."""
        with self._lock:
            return self._dispatch_count

    @property
    def error_count(self) -> int:
        """Total number of hook dispatches that ended in error."""
        with self._lock:
            return self._error_count

    @property
    def is_shutdown(self) -> bool:
        """Whether :meth:`shutdown` has been called."""
        return self._shutdown_event.is_set()

    # -- loading -----------------------------------------------------------

    def _load(self) -> None:
        """Load all enabled hooks from configuration.

        Raises on any failure — the application must not start with
        broken hooks.
        """
        for entry in self._settings.registered:
            if not entry.enabled:
                log.debug("Hook '%s' is disabled, skipping", entry.class_path)
                continue
            try:
                self._load_hook(entry)
            except Exception:
                log.critical(
                    "Failed to load hook '%s' — refusing to start",
                    entry.class_path,
                    exc_info=True,
                )
                raise

        if self._hooks:
            self._executor = ThreadPoolExecutor(
                max_workers=self._settings.max_workers,
                thread_name_prefix="acmeeh-hook",
            )
            log.info(
                "Loaded %d hook(s), executor pool=%d",
                len(self._hooks),
                self._settings.max_workers,
            )

    def _load_hook(self, entry: HookEntrySettings) -> None:
        """Import, validate, and instantiate a single hook.

        Parameters
        ----------
        entry:
            The hook entry configuration.

        """
        # Validate class_path format before touching importlib
        if not _CLASS_PATH_RE.match(entry.class_path):
            msg = (
                f"Invalid hook class path '{entry.class_path}': must match "
                "'package.module.ClassName' (only alphanumerics and underscores)"
            )
            raise ValueError(
                msg,
            )

        module_path, _, cls_name = entry.class_path.rpartition(".")
        if not module_path or not cls_name:
            msg = (
                f"Invalid hook class path '{entry.class_path}': must be "
                "fully qualified (e.g. 'mypackage.module.ClassName')"
            )
            raise ValueError(
                msg,
            )

        module = importlib.import_module(module_path)
        cls = getattr(module, cls_name)

        if not (isinstance(cls, type) and issubclass(cls, Hook)):
            msg = f"Hook '{entry.class_path}' must be a subclass of acmeeh.hooks.Hook"
            raise TypeError(
                msg,
            )

        # Validate hook-specific config before instantiation
        cls.validate_config(entry.config)

        instance = cls(config=entry.config)

        # Determine subscribed events
        if entry.events:
            unknown = frozenset(entry.events) - KNOWN_EVENTS
            if unknown:
                msg = (
                    f"Hook '{entry.class_path}' subscribes to unknown events: "
                    f"{sorted(unknown)}. Known events: {sorted(KNOWN_EVENTS)}"
                )
                raise ValueError(
                    msg,
                )
            subscribed = frozenset(entry.events)
        else:
            subscribed = KNOWN_EVENTS

        self._hooks.append(
            _LoadedHook(
                instance=instance,
                entry=entry,
                subscribed_events=subscribed,
            ),
        )
        log.info(
            "Loaded hook: %s (events=%s)",
            entry.class_path,
            "all" if subscribed == KNOWN_EVENTS else sorted(subscribed),
        )

    # -- dispatch ----------------------------------------------------------

    def dispatch(self, event: str, context: dict) -> None:
        """Dispatch an event to all subscribed hooks (fire-and-forget).

        Each hook runs in a thread pool worker.  The caller is never
        blocked — results are handled via done-callbacks.  Failures
        are logged but never propagated.

        Parameters
        ----------
        event:
            The event name (e.g. ``"certificate.issuance"``).
        context:
            Event-specific context dictionary.  Deep-copied once;
            each hook receives its own shallow copy.

        """
        if self._shutdown_event.is_set():
            return

        if not self._hooks or self._executor is None:
            return

        method_name = EVENT_METHOD_MAP.get(event)
        if method_name is None:
            msg = f"Unknown hook event '{event}'. Known events: {sorted(KNOWN_EVENTS)}"
            raise ValueError(
                msg,
            )

        timeout = self._settings.timeout_seconds

        # Deep-copy once to isolate hooks from the caller's dict
        base_context = copy.deepcopy(context)

        for loaded in self._hooks:
            if event not in loaded.subscribed_events:
                continue

            hook_timeout = (
                loaded.entry.timeout_seconds
                if loaded.entry.timeout_seconds is not None
                else timeout
            )

            # Shallow copy per hook — independent top-level keys
            hook_context = base_context.copy()

            try:
                future: Future = self._executor.submit(
                    self._execute_hook,
                    loaded,
                    method_name,
                    hook_context,
                    event,
                    hook_timeout,
                )
                future.add_done_callback(
                    lambda f, _l=loaded, _e=event, _t=hook_timeout: self._on_hook_done(
                        f, _l, _e, _t
                    ),  # type: ignore[misc]
                )
            except RuntimeError:
                log.warning(
                    "Executor shut down, cannot dispatch '%s' to '%s'",
                    event,
                    loaded.entry.class_path,
                )

    def _execute_hook(
        self,
        loaded: _LoadedHook,
        method_name: str,
        context: dict,
        event: str,
        timeout: int,
    ) -> dict[str, Any]:
        """Run a single hook method with optional retries."""
        max_retries = self._settings.max_retries
        start = time.monotonic()

        for retry in range(max_retries + 1):
            try:
                getattr(loaded.instance, method_name)(context)
                elapsed_ms = (time.monotonic() - start) * 1000
                return {
                    "hook_name": loaded.entry.class_path,
                    "event": event,
                    "outcome": "success",
                    "duration_ms": round(elapsed_ms, 2),
                }
            except Exception as exc:
                if retry < max_retries:
                    time.sleep(0.5 * (2**retry))
                    continue
                elapsed_ms = (time.monotonic() - start) * 1000
                return {
                    "hook_name": loaded.entry.class_path,
                    "event": event,
                    "outcome": "error",
                    "duration_ms": round(elapsed_ms, 2),
                    "error": str(exc),
                    "retries_exhausted": max_retries > 0,
                }

        # Should not be reached, but satisfy type checker
        elapsed_ms = (time.monotonic() - start) * 1000
        return {
            "hook_name": loaded.entry.class_path,
            "event": event,
            "outcome": "error",
            "duration_ms": round(elapsed_ms, 2),
            "error": "max retries exhausted",
            "retries_exhausted": True,
        }

    def _on_hook_done(
        self,
        future: Future,
        loaded: _LoadedHook,
        event: str,
        timeout: int,
    ) -> None:
        """Done-callback: structured logging + metrics update."""
        timeout_ms = timeout * 1000

        try:
            result = future.result(timeout=0)
        except Exception:
            # Future itself raised (e.g. cancelled) — shouldn't happen
            # in normal operation but guard defensively.
            with self._lock:
                self._dispatch_count += 1
                self._error_count += 1
            log.exception(
                "Hook future failed unexpectedly",
                extra={
                    "hook_name": loaded.entry.class_path,
                    "event": event,
                },
            )
            return

        with self._lock:
            self._dispatch_count += 1
            if result["outcome"] == "error":
                self._error_count += 1

        extra = {
            "hook_name": result["hook_name"],
            "event": result["event"],
            "outcome": result["outcome"],
            "duration_ms": result["duration_ms"],
        }

        if result["outcome"] == "error":
            log.error(
                "Hook '%s' raised an exception for event '%s' (%.1fms): %s",
                result["hook_name"],
                result["event"],
                result["duration_ms"],
                result.get("error", "unknown"),
                extra=extra,
            )
            # Dead-letter logging
            if result.get("retries_exhausted") and self._settings.dead_letter_log:
                self._write_dead_letter(result)
        elif result["duration_ms"] > timeout_ms:
            log.warning(
                "Hook '%s' exceeded timeout for event '%s' (%.1fms > %dms)",
                result["hook_name"],
                result["event"],
                result["duration_ms"],
                timeout_ms,
                extra=extra,
            )
        else:
            log.debug(
                "Hook '%s' completed event '%s' in %.1fms",
                result["hook_name"],
                result["event"],
                result["duration_ms"],
                extra=extra,
            )

    def _write_dead_letter(self, result: dict) -> None:
        """Append a failed hook result to the dead-letter log file."""
        try:
            import json

            entry = json.dumps(
                {
                    "timestamp": time.time(),
                    "hook_name": result["hook_name"],
                    "event": result["event"],
                    "error": result.get("error"),
                    "duration_ms": result["duration_ms"],
                }
            )
            with open(self._settings.dead_letter_log, "a") as f:  # type: ignore[arg-type]
                f.write(entry + "\n")
        except Exception:
            log.exception("Failed to write dead-letter log entry")

    # -- lifecycle ---------------------------------------------------------

    def shutdown(self, wait: bool = True) -> None:
        """Shutdown the thread pool executor.

        Guarded by a :class:`threading.Event` — safe to call multiple
        times, only the first call has effect.

        Parameters
        ----------
        wait:
            Whether to wait for pending tasks to complete.

        """
        if self._shutdown_event.is_set():
            return
        self._shutdown_event.set()

        if self._executor is not None:
            self._executor.shutdown(wait=wait)
            log.info(
                "Hook executor shut down (dispatched=%d, errors=%d)",
                self.dispatch_count,
                self.error_count,
            )
