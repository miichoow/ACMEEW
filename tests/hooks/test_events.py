"""Tests for acmeeh.hooks.events — KNOWN_EVENTS and EVENT_METHOD_MAP."""

from __future__ import annotations

from acmeeh.hooks.base import Hook
from acmeeh.hooks.events import EVENT_METHOD_MAP, KNOWN_EVENTS


class TestKnownEvents:
    def test_known_events_is_frozenset(self):
        assert isinstance(KNOWN_EVENTS, frozenset)

    def test_known_events_has_10_entries(self):
        assert len(KNOWN_EVENTS) == 10

    def test_all_specific_events_present(self):
        expected = {
            "account.registration",
            "order.creation",
            "challenge.before_validate",
            "challenge.after_validate",
            "challenge.on_failure",
            "challenge.on_retry",
            "certificate.issuance",
            "certificate.revocation",
            "certificate.delivery",
            "ct.submission",
        }
        assert expected == KNOWN_EVENTS


class TestEventMethodMap:
    def test_keys_match_known_events(self):
        assert set(EVENT_METHOD_MAP.keys()) == KNOWN_EVENTS

    def test_all_method_names_start_with_on(self):
        for method in EVENT_METHOD_MAP.values():
            assert method.startswith("on_"), f"{method} doesn't start with on_"

    def test_all_method_names_are_lowercase(self):
        for method in EVENT_METHOD_MAP.values():
            assert method == method.lower(), f"{method} is not lowercase"

    def test_no_duplicate_method_names(self):
        methods = list(EVENT_METHOD_MAP.values())
        assert len(methods) == len(set(methods))

    def test_methods_exist_on_hook_base_class(self):
        for method_name in EVENT_METHOD_MAP.values():
            assert hasattr(Hook, method_name), f"Hook base class missing method {method_name}"
