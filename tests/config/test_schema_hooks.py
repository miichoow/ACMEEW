"""Tests for the hooks section of the JSON Schema."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import ValidationError, validate

SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent.parent / "src" / "acmeeh" / "config" / "schema.json"
)


@pytest.fixture(scope="module")
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _minimal_config(**hooks_overrides) -> dict:
    """Return a minimal valid config dict with hooks section."""
    cfg = {
        "server": {"external_url": "https://acme.example.com"},
        "database": {"database": "acmeeh", "user": "acmeeh"},
    }
    if hooks_overrides:
        cfg["hooks"] = hooks_overrides
    return cfg


def _minimal_with_hook(**entry_overrides) -> dict:
    """Return a config with a single hook entry, merging *entry_overrides*."""
    entry = {"class": "mypackage.module.MyHook"}
    entry.update(entry_overrides)
    return _minimal_config(registered=[entry])


class TestSchemaHooksValid:
    def test_valid_hook_config_passes(self, schema):
        cfg = _minimal_with_hook(
            enabled=True,
            events=["certificate.issuance"],
            timeout_seconds=60,
            config={"key": "value"},
        )
        validate(instance=cfg, schema=schema)

    def test_all_known_events_pass(self, schema):
        events = [
            "account.registration",
            "order.creation",
            "challenge.before_validate",
            "challenge.after_validate",
            "challenge.on_failure",
            "challenge.on_retry",
            "certificate.issuance",
            "certificate.revocation",
            "certificate.delivery",
        ]
        cfg = _minimal_with_hook(events=events)
        validate(instance=cfg, schema=schema)

    def test_no_hooks_section_passes(self, schema):
        cfg = _minimal_config()
        validate(instance=cfg, schema=schema)


class TestSchemaHooksInvalid:
    def test_missing_class_field(self, schema):
        cfg = _minimal_config(registered=[{"enabled": True}])
        with pytest.raises(ValidationError, match="'class' is a required property"):
            validate(instance=cfg, schema=schema)

    def test_bad_class_path_no_dot(self, schema):
        cfg = _minimal_with_hook(**{"class": "NoDotHere"})
        with pytest.raises(ValidationError, match="pattern"):
            validate(instance=cfg, schema=schema)

    def test_bad_class_path_leading_dot(self, schema):
        cfg = _minimal_with_hook(**{"class": ".bad.Path"})
        with pytest.raises(ValidationError, match="pattern"):
            validate(instance=cfg, schema=schema)

    def test_unknown_event_string(self, schema):
        cfg = _minimal_with_hook(events=["bogus.event"])
        with pytest.raises(ValidationError):
            validate(instance=cfg, schema=schema)

    def test_timeout_seconds_too_low(self, schema):
        cfg = _minimal_with_hook(timeout_seconds=0)
        with pytest.raises(ValidationError, match="minimum"):
            validate(instance=cfg, schema=schema)

    def test_timeout_seconds_too_high(self, schema):
        cfg = _minimal_with_hook(timeout_seconds=301)
        with pytest.raises(ValidationError, match="maximum"):
            validate(instance=cfg, schema=schema)

    def test_config_max_properties(self, schema):
        big_config = {f"key_{i}": i for i in range(21)}
        cfg = _minimal_with_hook(config=big_config)
        with pytest.raises(ValidationError, match="maxProperties"):
            validate(instance=cfg, schema=schema)

    def test_registered_max_items(self, schema):
        entries = [{"class": f"pkg.mod.Hook{i}"} for i in range(51)]
        cfg = _minimal_config(registered=entries)
        with pytest.raises(ValidationError, match="maxItems"):
            validate(instance=cfg, schema=schema)
