"""Tests targeting uncovered lines in acmeeh.hooks.registry.HookRegistry.

Specifically covers:
- Lines 150-154: Defensive branch in _load_hook (module_path/cls_name empty)
- Lines 298-299: Retry path with time.sleep in _execute_hook
- Lines 311-312: Unreachable safety return after retry loop
- Lines 333-346: _on_hook_done when future.result() raises
- Line 372: dead_letter_log write path
- Line 374: timeout exceeded warning path
- Lines 394-406: _write_dead_letter normal + exception branches
"""

from __future__ import annotations

import json
import logging
import time
from concurrent.futures import Future
from unittest.mock import MagicMock, patch

import pytest
from tests.hooks.conftest import (
    DummyHook,
    FailingHook,
    make_hook_entry,
    make_hook_settings,
)

from acmeeh.hooks.base import Hook
from acmeeh.hooks.registry import HookRegistry, _LoadedHook

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _empty_registry(**kwargs) -> HookRegistry:
    """Build a HookRegistry with no hooks (skips _load doing real work)."""
    defaults = dict(
        registered=(),
        max_workers=2,
        timeout_seconds=30,
        max_retries=0,
        dead_letter_log=None,
    )
    defaults.update(kwargs)
    return HookRegistry(make_hook_settings(**defaults))


def _make_loaded(instance=None, class_path="test.DummyHook", events=frozenset()):
    """Build a _LoadedHook for direct method testing."""
    if instance is None:
        instance = DummyHook()
    entry = make_hook_entry(class_path=class_path)
    return _LoadedHook(
        instance=instance,
        entry=entry,
        subscribed_events=events,
    )


# =========================================================================
# Lines 150-154: _load_hook defensive branch (empty module_path or cls_name)
# =========================================================================


class TestLoadHookDefensiveBranch:
    """The regex already blocks most bad paths, but _load_hook has a second
    guard: ``if not module_path or not cls_name``.  We test this by calling
    _load_hook directly with a mocked entry that bypasses the regex check.
    """

    def test_empty_module_path_raises(self):
        """If rpartition gives empty module_path, ValueError is raised."""
        registry = _empty_registry()
        # A class_path like ".Foo" yields module_path="" after rpartition
        # but it fails the regex first.  So we mock the regex to pass:
        entry = make_hook_entry(class_path=".Foo")
        with patch("acmeeh.hooks.registry._CLASS_PATH_RE") as mock_re:
            mock_re.match.return_value = True  # pretend regex passes
            with pytest.raises(ValueError, match="must be fully qualified"):
                registry._load_hook(entry)
        registry.shutdown()

    def test_empty_cls_name_raises(self):
        """If rpartition gives empty cls_name, ValueError is raised."""
        registry = _empty_registry()
        entry = make_hook_entry(class_path="some.module.")
        with patch("acmeeh.hooks.registry._CLASS_PATH_RE") as mock_re:
            mock_re.match.return_value = True
            with pytest.raises(ValueError, match="must be fully qualified"):
                registry._load_hook(entry)
        registry.shutdown()

    def test_no_dot_at_all_raises(self):
        """A single token with no dots gives empty module_path."""
        registry = _empty_registry()
        entry = make_hook_entry(class_path="NoDots")
        with patch("acmeeh.hooks.registry._CLASS_PATH_RE") as mock_re:
            mock_re.match.return_value = True
            with pytest.raises(ValueError, match="must be fully qualified"):
                registry._load_hook(entry)
        registry.shutdown()


# =========================================================================
# Lines 298-299: retry path in _execute_hook
# =========================================================================


class TestExecuteHookRetry:
    """When max_retries > 0, _execute_hook retries on failure with
    exponential backoff via time.sleep.
    """

    def test_retry_succeeds_on_second_attempt(self):
        """Hook fails once then succeeds -> result is 'success'."""
        registry = _empty_registry(max_retries=1)
        call_count = 0

        class RetryHook(Hook):
            def on_certificate_issuance(self, ctx):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    raise RuntimeError("transient failure")

        loaded = _make_loaded(instance=RetryHook())
        with patch("acmeeh.hooks.registry.time.sleep") as mock_sleep:
            result = registry._execute_hook(
                loaded, "on_certificate_issuance", {}, "certificate.issuance", 30
            )
        assert result["outcome"] == "success"
        assert call_count == 2
        # Verify exponential backoff: 0.5 * (2 ** 0) = 0.5s
        mock_sleep.assert_called_once_with(0.5)
        registry.shutdown()

    def test_retry_all_fail_returns_error(self):
        """Hook fails on every retry -> result is 'error' with retries_exhausted."""
        registry = _empty_registry(max_retries=2)
        loaded = _make_loaded(instance=FailingHook())

        with patch("acmeeh.hooks.registry.time.sleep") as mock_sleep:
            result = registry._execute_hook(
                loaded, "on_certificate_issuance", {}, "certificate.issuance", 30
            )
        assert result["outcome"] == "error"
        assert result["retries_exhausted"] is True
        assert "boom" in result["error"]
        # Two sleeps: retry 0 (0.5 * 2^0 = 0.5) and retry 1 (0.5 * 2^1 = 1.0)
        assert mock_sleep.call_count == 2
        registry.shutdown()

    def test_retry_sleep_backoff_values(self):
        """Verify the exponential backoff durations."""
        registry = _empty_registry(max_retries=3)
        loaded = _make_loaded(instance=FailingHook())

        with patch("acmeeh.hooks.registry.time.sleep") as mock_sleep:
            registry._execute_hook(
                loaded, "on_certificate_issuance", {}, "certificate.issuance", 30
            )
        # Retries 0,1,2 sleep; retry 3 is the final failure (no sleep)
        assert mock_sleep.call_count == 3
        expected = [0.5, 1.0, 2.0]
        actual = [call.args[0] for call in mock_sleep.call_args_list]
        assert actual == expected
        registry.shutdown()

    def test_no_retry_when_max_retries_zero(self):
        """With max_retries=0, no retries happen."""
        registry = _empty_registry(max_retries=0)
        loaded = _make_loaded(instance=FailingHook())

        with patch("acmeeh.hooks.registry.time.sleep") as mock_sleep:
            result = registry._execute_hook(
                loaded, "on_certificate_issuance", {}, "certificate.issuance", 30
            )
        assert result["outcome"] == "error"
        assert result["retries_exhausted"] is False
        mock_sleep.assert_not_called()
        registry.shutdown()


# =========================================================================
# Lines 333-346: _on_hook_done when future.result() raises
# =========================================================================


class TestOnHookDoneFutureException:
    """When the Future itself raises (e.g. cancelled), _on_hook_done
    increments both counters and logs an exception.
    """

    def test_future_raises_increments_counts(self):
        registry = _empty_registry()
        loaded = _make_loaded()
        future = MagicMock(spec=Future)
        future.result.side_effect = RuntimeError("future cancelled")

        initial_dispatch = registry.dispatch_count
        initial_error = registry.error_count

        registry._on_hook_done(future, loaded, "certificate.issuance", 30)

        assert registry.dispatch_count == initial_dispatch + 1
        assert registry.error_count == initial_error + 1
        registry.shutdown()

    def test_future_raises_logs_exception(self, caplog):
        registry = _empty_registry()
        loaded = _make_loaded()
        future = MagicMock(spec=Future)
        future.result.side_effect = RuntimeError("cancelled by executor")

        with caplog.at_level(logging.ERROR):
            registry._on_hook_done(future, loaded, "certificate.issuance", 30)

        assert "Hook future failed unexpectedly" in caplog.text
        registry.shutdown()

    def test_future_raises_returns_early(self):
        """After the exception branch, nothing else should be called
        (no dead_letter_log write, no other logging path).
        """
        registry = _empty_registry(dead_letter_log="/tmp/dead.log")
        loaded = _make_loaded()
        future = MagicMock(spec=Future)
        future.result.side_effect = Exception("boom")

        with patch.object(registry, "_write_dead_letter") as mock_dl:
            registry._on_hook_done(future, loaded, "certificate.issuance", 30)
        mock_dl.assert_not_called()
        registry.shutdown()


# =========================================================================
# Line 372: dead_letter_log write path
# =========================================================================


class TestDeadLetterLogPath:
    """When result has retries_exhausted=True and dead_letter_log is set,
    _on_hook_done calls _write_dead_letter.
    """

    def test_dead_letter_triggered(self):
        registry = _empty_registry(dead_letter_log="/tmp/dead.log")
        loaded = _make_loaded()

        result = {
            "hook_name": "test.DummyHook",
            "event": "certificate.issuance",
            "outcome": "error",
            "duration_ms": 100.0,
            "error": "boom",
            "retries_exhausted": True,
        }
        future = MagicMock(spec=Future)
        future.result.return_value = result

        with patch.object(registry, "_write_dead_letter") as mock_dl:
            registry._on_hook_done(future, loaded, "certificate.issuance", 30)
        mock_dl.assert_called_once_with(result)
        registry.shutdown()

    def test_dead_letter_not_triggered_without_retries_exhausted(self):
        registry = _empty_registry(dead_letter_log="/tmp/dead.log")
        loaded = _make_loaded()

        result = {
            "hook_name": "test.DummyHook",
            "event": "certificate.issuance",
            "outcome": "error",
            "duration_ms": 100.0,
            "error": "boom",
            "retries_exhausted": False,
        }
        future = MagicMock(spec=Future)
        future.result.return_value = result

        with patch.object(registry, "_write_dead_letter") as mock_dl:
            registry._on_hook_done(future, loaded, "certificate.issuance", 30)
        mock_dl.assert_not_called()
        registry.shutdown()

    def test_dead_letter_not_triggered_without_log_path(self):
        registry = _empty_registry(dead_letter_log=None)
        loaded = _make_loaded()

        result = {
            "hook_name": "test.DummyHook",
            "event": "certificate.issuance",
            "outcome": "error",
            "duration_ms": 100.0,
            "error": "boom",
            "retries_exhausted": True,
        }
        future = MagicMock(spec=Future)
        future.result.return_value = result

        with patch.object(registry, "_write_dead_letter") as mock_dl:
            registry._on_hook_done(future, loaded, "certificate.issuance", 30)
        mock_dl.assert_not_called()
        registry.shutdown()


# =========================================================================
# Line 374: timeout exceeded warning path
# =========================================================================


class TestTimeoutExceededWarning:
    """When outcome is 'success' but duration_ms > timeout_ms, a warning
    is logged.
    """

    def test_slow_success_logs_warning(self, caplog):
        registry = _empty_registry()
        loaded = _make_loaded()

        result = {
            "hook_name": "test.DummyHook",
            "event": "certificate.issuance",
            "outcome": "success",
            "duration_ms": 35000.0,  # 35s
        }
        future = MagicMock(spec=Future)
        future.result.return_value = result

        with caplog.at_level(logging.WARNING):
            # timeout=30 means timeout_ms=30000
            registry._on_hook_done(future, loaded, "certificate.issuance", 30)

        assert "exceeded timeout" in caplog.text
        registry.shutdown()

    def test_fast_success_logs_debug(self, caplog):
        registry = _empty_registry()
        loaded = _make_loaded()

        result = {
            "hook_name": "test.DummyHook",
            "event": "certificate.issuance",
            "outcome": "success",
            "duration_ms": 10.0,  # well within timeout
        }
        future = MagicMock(spec=Future)
        future.result.return_value = result

        with caplog.at_level(logging.DEBUG):
            registry._on_hook_done(future, loaded, "certificate.issuance", 30)

        assert "completed event" in caplog.text
        registry.shutdown()

    def test_exactly_at_timeout_no_warning(self, caplog):
        """When duration_ms == timeout_ms, no warning (only > triggers)."""
        registry = _empty_registry()
        loaded = _make_loaded()

        result = {
            "hook_name": "test.DummyHook",
            "event": "certificate.issuance",
            "outcome": "success",
            "duration_ms": 30000.0,  # exactly 30s
        }
        future = MagicMock(spec=Future)
        future.result.return_value = result

        with caplog.at_level(logging.WARNING):
            registry._on_hook_done(future, loaded, "certificate.issuance", 30)

        assert "exceeded timeout" not in caplog.text
        registry.shutdown()


# =========================================================================
# Lines 394-406: _write_dead_letter
# =========================================================================


class TestWriteDeadLetter:
    """Direct tests for the _write_dead_letter method."""

    def test_writes_json_to_file(self, tmp_path):
        dead_log = str(tmp_path / "dead_letter.log")
        registry = _empty_registry(dead_letter_log=dead_log)

        result = {
            "hook_name": "test.FailingHook",
            "event": "certificate.issuance",
            "error": "boom",
            "duration_ms": 123.45,
        }
        registry._write_dead_letter(result)

        with open(dead_log) as f:
            lines = f.readlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["hook_name"] == "test.FailingHook"
        assert entry["event"] == "certificate.issuance"
        assert entry["error"] == "boom"
        assert entry["duration_ms"] == 123.45
        assert "timestamp" in entry
        registry.shutdown()

    def test_appends_multiple_entries(self, tmp_path):
        dead_log = str(tmp_path / "dead_letter.log")
        registry = _empty_registry(dead_letter_log=dead_log)

        for i in range(3):
            registry._write_dead_letter(
                {
                    "hook_name": f"hook_{i}",
                    "event": "certificate.issuance",
                    "error": f"error_{i}",
                    "duration_ms": float(i),
                }
            )

        with open(dead_log) as f:
            lines = f.readlines()
        assert len(lines) == 3
        for i, line in enumerate(lines):
            entry = json.loads(line)
            assert entry["hook_name"] == f"hook_{i}"
        registry.shutdown()

    def test_write_failure_logs_exception(self, caplog):
        registry = _empty_registry(dead_letter_log="/nonexistent/path/dead.log")

        result = {
            "hook_name": "test.FailingHook",
            "event": "certificate.issuance",
            "error": "boom",
            "duration_ms": 100.0,
        }

        with caplog.at_level(logging.ERROR):
            # Should not raise, just log
            registry._write_dead_letter(result)

        assert "Failed to write dead-letter log entry" in caplog.text
        registry.shutdown()

    def test_timestamp_is_recent(self, tmp_path):
        dead_log = str(tmp_path / "dead_letter.log")
        registry = _empty_registry(dead_letter_log=dead_log)

        before = time.time()
        registry._write_dead_letter(
            {
                "hook_name": "test.Hook",
                "event": "certificate.issuance",
                "error": "err",
                "duration_ms": 1.0,
            }
        )
        after = time.time()

        with open(dead_log) as f:
            entry = json.loads(f.readline())
        assert before <= entry["timestamp"] <= after
        registry.shutdown()


# =========================================================================
# Integration: retry + dead_letter via _on_hook_done
# =========================================================================


class TestRetryDeadLetterIntegration:
    """End-to-end: failing hook with retries -> dead letter log."""

    def test_retries_exhausted_writes_dead_letter(self, tmp_path):
        dead_log = str(tmp_path / "dead.log")
        registry = _empty_registry(max_retries=2, dead_letter_log=dead_log)
        loaded = _make_loaded(instance=FailingHook())

        with patch("acmeeh.hooks.registry.time.sleep"):
            result = registry._execute_hook(
                loaded, "on_certificate_issuance", {}, "certificate.issuance", 30
            )

        assert result["outcome"] == "error"
        assert result["retries_exhausted"] is True

        # Feed it through _on_hook_done
        future = MagicMock(spec=Future)
        future.result.return_value = result
        registry._on_hook_done(future, loaded, "certificate.issuance", 30)

        with open(dead_log) as f:
            entry = json.loads(f.readline())
        assert entry["hook_name"] == "test.DummyHook"
        assert entry["error"] == "boom"
        registry.shutdown()
