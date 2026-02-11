"""Tests for _build_hooks() in acmeeh.config.settings."""

from __future__ import annotations

import dataclasses

import pytest

from acmeeh.config.settings import (
    _build_hooks,
)
from acmeeh.hooks.events import KNOWN_EVENTS


class TestBuildHooksDefaults:
    def test_none_returns_defaults(self):
        result = _build_hooks(None)
        assert result.timeout_seconds == 30
        assert result.max_workers == 4
        assert result.registered == ()

    def test_empty_dict_returns_defaults(self):
        result = _build_hooks({})
        assert result.timeout_seconds == 30
        assert result.max_workers == 4
        assert result.registered == ()


class TestBuildHooksCustom:
    def test_custom_timeout_and_max_workers(self):
        result = _build_hooks({"timeout_seconds": 60, "max_workers": 8})
        assert result.timeout_seconds == 60
        assert result.max_workers == 8

    def test_single_entry_all_fields(self):
        data = {
            "registered": [
                {
                    "class": "my.hooks.AuditHook",
                    "enabled": False,
                    "events": ["certificate.issuance", "certificate.revocation"],
                    "timeout_seconds": 10,
                    "config": {"endpoint": "https://siem.example.com"},
                }
            ]
        }
        result = _build_hooks(data)
        assert len(result.registered) == 1
        entry = result.registered[0]
        assert entry.class_path == "my.hooks.AuditHook"
        assert entry.enabled is False
        assert entry.events == ("certificate.issuance", "certificate.revocation")
        assert entry.timeout_seconds == 10
        assert entry.config == {"endpoint": "https://siem.example.com"}

    def test_entry_missing_optional_fields_defaults(self):
        data = {"registered": [{"class": "pkg.mod.Hook"}]}
        result = _build_hooks(data)
        entry = result.registered[0]
        assert entry.enabled is True
        assert entry.events == ()
        assert entry.timeout_seconds is None
        assert entry.config == {}


class TestBuildHooksValidation:
    def test_unknown_event_raises(self):
        data = {"registered": [{"class": "pkg.mod.Hook", "events": ["bogus.event"]}]}
        with pytest.raises(ValueError, match="unknown event.*bogus.event"):
            _build_hooks(data)

    def test_all_known_events_accepted(self):
        data = {"registered": [{"class": "pkg.mod.Hook", "events": sorted(KNOWN_EVENTS)}]}
        result = _build_hooks(data)
        assert set(result.registered[0].events) == KNOWN_EVENTS

    def test_empty_events_list_gives_empty_tuple(self):
        data = {"registered": [{"class": "pkg.mod.Hook", "events": []}]}
        result = _build_hooks(data)
        assert result.registered[0].events == ()


class TestBuildHooksImmutability:
    def test_hook_settings_frozen(self):
        result = _build_hooks(None)
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.timeout_seconds = 999

    def test_registered_is_tuple(self):
        result = _build_hooks(None)
        assert isinstance(result.registered, tuple)

    def test_hook_entry_frozen(self):
        data = {"registered": [{"class": "pkg.mod.Hook"}]}
        result = _build_hooks(data)
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.registered[0].class_path = "other"

    def test_events_is_tuple(self):
        data = {"registered": [{"class": "pkg.mod.Hook", "events": ["certificate.issuance"]}]}
        result = _build_hooks(data)
        assert isinstance(result.registered[0].events, tuple)
