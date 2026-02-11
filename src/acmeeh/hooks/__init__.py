"""Lifecycle hooks subsystem for ACMEEH.

Public API::

    from acmeeh.hooks import Hook, HookRegistry, KNOWN_EVENTS

    class MyHook(Hook):
        def on_certificate_issuance(self, ctx: dict) -> None:
            ...
"""

from acmeeh.hooks.base import Hook
from acmeeh.hooks.events import KNOWN_EVENTS
from acmeeh.hooks.registry import HookRegistry

__all__ = ["KNOWN_EVENTS", "Hook", "HookRegistry"]
