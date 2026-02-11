"""Hook-specific fixtures for testing."""

from __future__ import annotations

import time
import types
from typing import Any
from unittest.mock import patch

import pytest

from acmeeh.config.settings import HookEntrySettings, HookSettings
from acmeeh.hooks.base import Hook

# ---------------------------------------------------------------------------
# Concrete Hook subclasses for testing
# ---------------------------------------------------------------------------


class DummyHook(Hook):
    """Records every call in ``self.calls``."""

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        self.calls: list[tuple[str, dict]] = []

    def _record(self, method: str, ctx: dict) -> None:
        self.calls.append((method, ctx))

    def on_account_registration(self, ctx: dict) -> None:
        self._record("on_account_registration", ctx)

    def on_order_creation(self, ctx: dict) -> None:
        self._record("on_order_creation", ctx)

    def on_challenge_before_validate(self, ctx: dict) -> None:
        self._record("on_challenge_before_validate", ctx)

    def on_challenge_after_validate(self, ctx: dict) -> None:
        self._record("on_challenge_after_validate", ctx)

    def on_challenge_failure(self, ctx: dict) -> None:
        self._record("on_challenge_failure", ctx)

    def on_challenge_retry(self, ctx: dict) -> None:
        self._record("on_challenge_retry", ctx)

    def on_certificate_issuance(self, ctx: dict) -> None:
        self._record("on_certificate_issuance", ctx)

    def on_certificate_revocation(self, ctx: dict) -> None:
        self._record("on_certificate_revocation", ctx)

    def on_certificate_delivery(self, ctx: dict) -> None:
        self._record("on_certificate_delivery", ctx)

    def on_ct_submission(self, ctx: dict) -> None:
        self._record("on_ct_submission", ctx)


class FailingHook(Hook):
    """Raises RuntimeError on every event method."""

    def on_account_registration(self, ctx: dict) -> None:
        raise RuntimeError("boom")

    def on_order_creation(self, ctx: dict) -> None:
        raise RuntimeError("boom")

    def on_challenge_before_validate(self, ctx: dict) -> None:
        raise RuntimeError("boom")

    def on_challenge_after_validate(self, ctx: dict) -> None:
        raise RuntimeError("boom")

    def on_challenge_failure(self, ctx: dict) -> None:
        raise RuntimeError("boom")

    def on_challenge_retry(self, ctx: dict) -> None:
        raise RuntimeError("boom")

    def on_certificate_issuance(self, ctx: dict) -> None:
        raise RuntimeError("boom")

    def on_certificate_revocation(self, ctx: dict) -> None:
        raise RuntimeError("boom")

    def on_certificate_delivery(self, ctx: dict) -> None:
        raise RuntimeError("boom")

    def on_ct_submission(self, ctx: dict) -> None:
        raise RuntimeError("boom")


class SlowHook(Hook):
    """Sleeps for a configurable duration on every event."""

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        self.duration = self.config.get("sleep_seconds", 0.5)

    def on_certificate_issuance(self, ctx: dict) -> None:
        time.sleep(self.duration)


class ValidatingHook(Hook):
    """``validate_config`` requires ``required_key`` in config."""

    @classmethod
    def validate_config(cls, config: dict) -> None:
        if "required_key" not in config:
            raise ValueError("missing required_key")


class ContextMutatingHook(Hook):
    """Mutates the received context dict (for isolation tests)."""

    def on_certificate_issuance(self, ctx: dict) -> None:
        ctx["mutated_by"] = "ContextMutatingHook"
        ctx["nested"] = {"injected": True}


class NotAHook:
    """Not a Hook subclass — used for TypeError tests."""

    pass


# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------


def make_hook_entry(
    class_path: str = "fake_hooks.DummyHook",
    enabled: bool = True,
    events: tuple[str, ...] = (),
    timeout_seconds: int | None = None,
    config: dict[str, Any] | None = None,
) -> HookEntrySettings:
    return HookEntrySettings(
        class_path=class_path,
        enabled=enabled,
        events=events,
        timeout_seconds=timeout_seconds,
        config=config or {},
    )


def make_hook_settings(
    timeout_seconds: int = 30,
    max_workers: int = 2,
    max_retries: int = 0,
    dead_letter_log: str | None = None,
    registered: tuple[HookEntrySettings, ...] = (),
) -> HookSettings:
    return HookSettings(
        timeout_seconds=timeout_seconds,
        max_workers=max_workers,
        max_retries=max_retries,
        dead_letter_log=dead_letter_log,
        registered=registered,
    )


# ---------------------------------------------------------------------------
# Fake module for importlib mocking
# ---------------------------------------------------------------------------


def _make_fake_module() -> types.ModuleType:
    """Build a ``types.ModuleType`` containing all test hook classes."""
    mod = types.ModuleType("fake_hooks")
    mod.DummyHook = DummyHook
    mod.FailingHook = FailingHook
    mod.SlowHook = SlowHook
    mod.ValidatingHook = ValidatingHook
    mod.ContextMutatingHook = ContextMutatingHook
    mod.NotAHook = NotAHook
    return mod


@pytest.fixture()
def fake_module():
    """Return a fake module object with test hook classes."""
    return _make_fake_module()


@pytest.fixture()
def registry_with_hooks(fake_module):
    """Patch ``importlib.import_module`` and yield a factory function.

    Usage in tests::

        def test_x(registry_with_hooks):
            registry = registry_with_hooks(entries=[...])
            ...
    """
    from acmeeh.hooks.registry import HookRegistry

    def _factory(
        entries: list[HookEntrySettings] | None = None,
        timeout_seconds: int = 30,
        max_workers: int = 2,
    ) -> HookRegistry:
        if entries is None:
            entries = [make_hook_entry()]
        settings = make_hook_settings(
            timeout_seconds=timeout_seconds,
            max_workers=max_workers,
            registered=tuple(entries),
        )
        with patch("acmeeh.hooks.registry.importlib.import_module", return_value=fake_module):
            return HookRegistry(settings)

    return _factory
