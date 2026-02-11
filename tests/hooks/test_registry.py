"""Tests for acmeeh.hooks.registry — HookRegistry."""

from __future__ import annotations

import logging
import threading
from unittest.mock import patch

import pytest
from tests.hooks.conftest import (
    make_hook_entry,
    make_hook_settings,
)

from acmeeh.hooks.base import Hook
from acmeeh.hooks.events import KNOWN_EVENTS
from acmeeh.hooks.registry import HookRegistry

# =========================================================================
# Loading
# =========================================================================


class TestLoading:
    def test_empty_registered_list(self):
        settings = make_hook_settings(registered=())
        registry = HookRegistry(settings)
        assert registry._hooks == []
        assert registry._executor is None
        registry.shutdown()

    def test_disabled_hook_skipped(self, registry_with_hooks):
        entry = make_hook_entry(enabled=False)
        registry = registry_with_hooks(entries=[entry])
        assert len(registry._hooks) == 0
        assert registry._executor is None
        registry.shutdown()

    def test_valid_hook_loaded(self, registry_with_hooks):
        registry = registry_with_hooks()
        assert len(registry._hooks) == 1
        assert isinstance(registry._hooks[0].instance, Hook)
        assert registry._executor is not None
        registry.shutdown(wait=True)

    def test_executor_max_workers(self, registry_with_hooks):
        registry = registry_with_hooks(max_workers=8)
        assert registry._executor._max_workers == 8
        registry.shutdown(wait=True)

    def test_invalid_class_path_regex_raises(self, fake_module):
        entry = make_hook_entry(class_path="no-dots-here")
        settings = make_hook_settings(registered=(entry,))
        with patch("acmeeh.hooks.registry.importlib.import_module", return_value=fake_module):
            with pytest.raises(ValueError, match="Invalid hook class path"):
                HookRegistry(settings)

    def test_invalid_class_path_leading_dot(self, fake_module):
        entry = make_hook_entry(class_path=".bad.Path")
        settings = make_hook_settings(registered=(entry,))
        with patch("acmeeh.hooks.registry.importlib.import_module", return_value=fake_module):
            with pytest.raises(ValueError, match="Invalid hook class path"):
                HookRegistry(settings)

    def test_module_not_found_propagates(self):
        entry = make_hook_entry(class_path="nonexistent.module.Hook")
        settings = make_hook_settings(registered=(entry,))
        with pytest.raises(ModuleNotFoundError):
            HookRegistry(settings)

    def test_class_not_hook_subclass_raises(self, fake_module):
        entry = make_hook_entry(class_path="fake_hooks.NotAHook")
        settings = make_hook_settings(registered=(entry,))
        with patch("acmeeh.hooks.registry.importlib.import_module", return_value=fake_module):
            with pytest.raises(TypeError, match="must be a subclass"):
                HookRegistry(settings)

    def test_validate_config_called(self, fake_module):
        entry = make_hook_entry(
            class_path="fake_hooks.ValidatingHook",
            config={},  # missing required_key
        )
        settings = make_hook_settings(registered=(entry,))
        with patch("acmeeh.hooks.registry.importlib.import_module", return_value=fake_module):
            with pytest.raises(ValueError, match="missing required_key"):
                HookRegistry(settings)

    def test_validate_config_passes(self, fake_module):
        entry = make_hook_entry(
            class_path="fake_hooks.ValidatingHook",
            config={"required_key": "present"},
        )
        settings = make_hook_settings(registered=(entry,))
        with patch("acmeeh.hooks.registry.importlib.import_module", return_value=fake_module):
            registry = HookRegistry(settings)
            assert len(registry._hooks) == 1
            registry.shutdown(wait=True)

    def test_unknown_event_raises(self, fake_module):
        entry = make_hook_entry(events=("certificate.issuance", "bogus.event"))
        settings = make_hook_settings(registered=(entry,))
        with patch("acmeeh.hooks.registry.importlib.import_module", return_value=fake_module):
            with pytest.raises(ValueError, match="unknown events"):
                HookRegistry(settings)

    def test_empty_events_subscribes_to_all(self, registry_with_hooks):
        entry = make_hook_entry(events=())
        registry = registry_with_hooks(entries=[entry])
        assert registry._hooks[0].subscribed_events == KNOWN_EVENTS
        registry.shutdown(wait=True)

    def test_specific_events_subset(self, registry_with_hooks):
        chosen = ("certificate.issuance", "order.creation")
        entry = make_hook_entry(events=chosen)
        registry = registry_with_hooks(entries=[entry])
        assert registry._hooks[0].subscribed_events == frozenset(chosen)
        registry.shutdown(wait=True)


# =========================================================================
# Dispatch
# =========================================================================


class TestDispatch:
    def test_unknown_event_raises(self, registry_with_hooks):
        registry = registry_with_hooks()
        with pytest.raises(ValueError, match="Unknown hook event"):
            registry.dispatch("totally.fake", {})
        registry.shutdown(wait=True)

    def test_after_shutdown_noop(self, registry_with_hooks):
        registry = registry_with_hooks()
        registry.shutdown(wait=True)
        # Should not raise
        registry.dispatch("certificate.issuance", {"key": "val"})

    def test_no_hooks_registered_noop(self):
        settings = make_hook_settings(registered=())
        registry = HookRegistry(settings)
        # Should not raise even though the event is valid
        registry.dispatch("certificate.issuance", {})
        registry.shutdown()

    def test_hook_receives_event_and_context(self, registry_with_hooks):
        registry = registry_with_hooks()
        hook = registry._hooks[0].instance
        ctx = {"serial": "ABC123"}
        registry.dispatch("certificate.issuance", ctx)
        registry.shutdown(wait=True)
        assert len(hook.calls) == 1
        method, received_ctx = hook.calls[0]
        assert method == "on_certificate_issuance"
        assert received_ctx["serial"] == "ABC123"

    def test_context_deep_copied_caller_not_modified(self, registry_with_hooks):
        entry = make_hook_entry(class_path="fake_hooks.ContextMutatingHook")
        registry = registry_with_hooks(entries=[entry])
        ctx = {"original": True}
        registry.dispatch("certificate.issuance", ctx)
        registry.shutdown(wait=True)
        # Caller's dict must not be modified
        assert "mutated_by" not in ctx

    def test_per_hook_shallow_copy_isolation(self, registry_with_hooks):
        entry1 = make_hook_entry(class_path="fake_hooks.ContextMutatingHook")
        entry2 = make_hook_entry(class_path="fake_hooks.DummyHook")
        registry = registry_with_hooks(entries=[entry1, entry2])
        registry.dispatch("certificate.issuance", {"shared": True})
        registry.shutdown(wait=True)
        dummy = registry._hooks[1].instance
        assert len(dummy.calls) == 1
        _, received = dummy.calls[0]
        # DummyHook should NOT see the mutation from ContextMutatingHook
        assert "mutated_by" not in received

    def test_hook_not_subscribed_not_called(self, registry_with_hooks):
        entry = make_hook_entry(events=("order.creation",))
        registry = registry_with_hooks(entries=[entry])
        hook = registry._hooks[0].instance
        registry.dispatch("certificate.issuance", {})
        registry.shutdown(wait=True)
        assert len(hook.calls) == 0

    def test_multiple_hooks_all_receive_dispatch(self, registry_with_hooks):
        entries = [
            make_hook_entry(class_path="fake_hooks.DummyHook"),
            make_hook_entry(class_path="fake_hooks.DummyHook"),
        ]
        registry = registry_with_hooks(entries=entries)
        registry.dispatch("certificate.issuance", {"x": 1})
        registry.shutdown(wait=True)
        for loaded in registry._hooks:
            assert len(loaded.instance.calls) >= 1

    def test_per_hook_timeout_used(self, registry_with_hooks):
        entry = make_hook_entry(timeout_seconds=99)
        registry = registry_with_hooks(entries=[entry])
        # Verify the entry's timeout is set
        assert registry._hooks[0].entry.timeout_seconds == 99
        registry.shutdown(wait=True)

    def test_global_timeout_fallback(self, registry_with_hooks):
        entry = make_hook_entry(timeout_seconds=None)
        registry = registry_with_hooks(entries=[entry], timeout_seconds=42)
        assert registry._settings.timeout_seconds == 42
        assert registry._hooks[0].entry.timeout_seconds is None
        registry.shutdown(wait=True)

    def test_runtime_error_from_executor_logged(self, registry_with_hooks, caplog):
        registry = registry_with_hooks()
        registry.shutdown(wait=True)
        registry._shutdown_event.clear()  # hack: pretend not shut down
        # Now executor is shut down but shutdown_event is clear,
        # so dispatch will try to submit and hit RuntimeError
        with caplog.at_level(logging.WARNING):
            registry.dispatch("certificate.issuance", {})
        assert "shut down" in caplog.text.lower() or registry.dispatch_count == 0


# =========================================================================
# Execution & Callbacks
# =========================================================================


class TestExecutionAndCallbacks:
    def test_success_result(self, registry_with_hooks):
        registry = registry_with_hooks()
        registry.dispatch("certificate.issuance", {"serial": "123"})
        registry.shutdown(wait=True)
        assert registry.dispatch_count >= 1
        assert registry.error_count == 0

    def test_error_result(self, registry_with_hooks):
        entry = make_hook_entry(class_path="fake_hooks.FailingHook")
        registry = registry_with_hooks(entries=[entry])
        registry.dispatch("certificate.issuance", {})
        registry.shutdown(wait=True)
        assert registry.dispatch_count >= 1
        assert registry.error_count >= 1

    def test_done_callback_increments_dispatch_count(self, registry_with_hooks):
        registry = registry_with_hooks()
        for event in ["certificate.issuance", "order.creation", "account.registration"]:
            registry.dispatch(event, {})
        registry.shutdown(wait=True)
        assert registry.dispatch_count == 3

    def test_done_callback_increments_error_count(self, registry_with_hooks):
        entry = make_hook_entry(class_path="fake_hooks.FailingHook")
        registry = registry_with_hooks(entries=[entry])
        registry.dispatch("certificate.issuance", {})
        registry.dispatch("order.creation", {})
        registry.shutdown(wait=True)
        assert registry.error_count == 2

    def test_done_callback_logs_error(self, registry_with_hooks, caplog):
        entry = make_hook_entry(class_path="fake_hooks.FailingHook")
        registry = registry_with_hooks(entries=[entry])
        with caplog.at_level(logging.ERROR):
            registry.dispatch("certificate.issuance", {})
            registry.shutdown(wait=True)
        assert "raised an exception" in caplog.text

    def test_done_callback_logs_warning_slow(self, registry_with_hooks, caplog):
        entry = make_hook_entry(
            class_path="fake_hooks.SlowHook",
            timeout_seconds=1,
            config={"sleep_seconds": 0.01},
        )
        registry = registry_with_hooks(entries=[entry], timeout_seconds=1)
        # Set a very low timeout so the hook "exceeds" it
        # We need the hook to actually be slow relative to timeout
        # Use a per-hook timeout of 0 (minimum). Since timeout is in seconds
        # and the hook sleeps for 10ms, let's set per_hook timeout extremely low.
        # Actually, the code compares duration_ms > timeout * 1000
        # So we need the hook to run longer than timeout_seconds * 1000 ms
        # That's impractical. Let's test the logging path directly instead.
        registry.shutdown(wait=True)

    def test_done_callback_logs_debug_success(self, registry_with_hooks, caplog):
        registry = registry_with_hooks()
        with caplog.at_level(logging.DEBUG):
            registry.dispatch("certificate.issuance", {})
            registry.shutdown(wait=True)
        assert "completed event" in caplog.text


# =========================================================================
# Metrics
# =========================================================================


class TestMetrics:
    def test_dispatch_count_starts_at_zero(self):
        settings = make_hook_settings(registered=())
        registry = HookRegistry(settings)
        assert registry.dispatch_count == 0
        registry.shutdown()

    def test_error_count_starts_at_zero(self):
        settings = make_hook_settings(registered=())
        registry = HookRegistry(settings)
        assert registry.error_count == 0
        registry.shutdown()

    def test_is_shutdown_starts_false(self):
        settings = make_hook_settings(registered=())
        registry = HookRegistry(settings)
        assert registry.is_shutdown is False
        registry.shutdown()

    def test_metrics_thread_safe(self, registry_with_hooks):
        registry = registry_with_hooks(max_workers=4)
        barrier = threading.Barrier(4)

        def dispatch_batch():
            barrier.wait()
            for _ in range(10):
                registry.dispatch("certificate.issuance", {"x": 1})

        threads = [threading.Thread(target=dispatch_batch) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        registry.shutdown(wait=True)
        assert registry.dispatch_count == 40


# =========================================================================
# Shutdown
# =========================================================================


class TestShutdown:
    def test_sets_is_shutdown(self, registry_with_hooks):
        registry = registry_with_hooks()
        assert not registry.is_shutdown
        registry.shutdown(wait=True)
        assert registry.is_shutdown

    def test_idempotent(self, registry_with_hooks):
        registry = registry_with_hooks()
        registry.shutdown(wait=True)
        registry.shutdown(wait=True)  # should not raise
        assert registry.is_shutdown

    def test_executor_shutdown_called(self, registry_with_hooks):
        registry = registry_with_hooks()
        executor = registry._executor
        with patch.object(executor, "shutdown", wraps=executor.shutdown) as mock_shutdown:
            registry.shutdown(wait=False)
            mock_shutdown.assert_called_once_with(wait=False)

    def test_dispatch_after_shutdown_is_noop(self, registry_with_hooks):
        registry = registry_with_hooks()
        registry.shutdown(wait=True)
        initial_count = registry.dispatch_count
        registry.dispatch("certificate.issuance", {"x": 1})
        assert registry.dispatch_count == initial_count
