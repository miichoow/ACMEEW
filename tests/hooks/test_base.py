"""Tests for acmeeh.hooks.base — Hook ABC."""

from __future__ import annotations

import abc

import pytest

from acmeeh.hooks.base import Hook
from acmeeh.hooks.events import EVENT_METHOD_MAP


class TestHookInit:
    def test_init_none_config_gives_empty_dict(self):
        class Concrete(Hook):
            pass

        h = Concrete(config=None)
        assert h.config == {}

    def test_init_empty_dict_config(self):
        class Concrete(Hook):
            pass

        h = Concrete(config={})
        assert h.config == {}

    def test_init_explicit_config_stored(self):
        class Concrete(Hook):
            pass

        cfg = {"key": "value", "n": 42}
        h = Concrete(config=cfg)
        assert h.config == cfg

    def test_init_no_args(self):
        class Concrete(Hook):
            pass

        h = Concrete()
        assert h.config == {}


class TestHookABC:
    def test_hook_inherits_from_abc(self):
        assert issubclass(Hook, abc.ABC)


class TestValidateConfig:
    def test_default_validate_config_is_noop(self):
        # Should not raise
        Hook.validate_config({})
        Hook.validate_config({"anything": "goes"})

    def test_subclass_can_override_validate_config(self):
        class Strict(Hook):
            @classmethod
            def validate_config(cls, config: dict) -> None:
                if "must_have" not in config:
                    raise ValueError("missing must_have")

        with pytest.raises(ValueError, match="missing must_have"):
            Strict.validate_config({})

        # Should pass
        Strict.validate_config({"must_have": True})


class TestEventMethods:
    def test_all_event_methods_callable_noop(self):
        class Concrete(Hook):
            pass

        h = Concrete()
        for method_name in EVENT_METHOD_MAP.values():
            # Should not raise and return None
            result = getattr(h, method_name)({"test": True})
            assert result is None

    def test_subclass_can_override_event_method(self):
        class Custom(Hook):
            def __init__(self, config=None):
                super().__init__(config)
                self.called = False

            def on_certificate_issuance(self, ctx: dict) -> None:
                self.called = True

        h = Custom()
        assert not h.called
        h.on_certificate_issuance({"serial": "123"})
        assert h.called
