"""Tests for admin_api config validation."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from acmeeh.config.acmeeh_config import AcmeehConfig, ConfigValidationError


def _write_config(tmp_path: Path, data: dict) -> Path:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        yaml.safe_dump(data, default_flow_style=False, sort_keys=False), encoding="utf-8"
    )
    return cfg


def _base_config(**admin_overrides) -> dict:
    cfg = {
        "server": {"external_url": "https://acme.example.com"},
        "database": {"database": "acmeeh_test", "user": "testuser"},
        "ca": {
            "internal": {
                "root_cert_path": "/tmp/root.pem",
                "root_key_path": "/tmp/root.key",
            }
        },
    }
    if admin_overrides:
        cfg["admin_api"] = admin_overrides
    return cfg


class TestAdminApiValidation:
    def test_disabled_by_default(self, tmp_path):
        cfg_path = _write_config(tmp_path, _base_config())
        config = AcmeehConfig(config_file=str(cfg_path), schema_file="bundled")
        assert config.settings.admin_api.enabled is False

    def test_enabled_requires_email(self, tmp_path):
        cfg_path = _write_config(
            tmp_path,
            _base_config(
                enabled=True,
                base_path="/admin",
            ),
        )
        with pytest.raises(ConfigValidationError) as exc_info:
            AcmeehConfig(config_file=str(cfg_path), schema_file="bundled")
        errors = exc_info.value.errors
        assert any("initial_admin_email" in e for e in errors)

    def test_base_path_collision(self, tmp_path):
        data = _base_config(
            enabled=True,
            base_path="",  # same as default api.base_path
            initial_admin_email="admin@example.com",
        )
        cfg_path = _write_config(tmp_path, data)
        with pytest.raises(ConfigValidationError) as exc_info:
            AcmeehConfig(config_file=str(cfg_path), schema_file="bundled")
        errors = exc_info.value.errors
        assert any("collide" in e for e in errors)

    def test_valid_config(self, tmp_path):
        cfg_path = _write_config(
            tmp_path,
            _base_config(
                enabled=True,
                base_path="/admin",
                initial_admin_email="admin@example.com",
                token_secret="my-secret-key-long-enough",
            ),
        )
        config = AcmeehConfig(config_file=str(cfg_path), schema_file="bundled")
        assert config.settings.admin_api.enabled is True
        assert config.settings.admin_api.base_path == "/admin"
        assert config.settings.admin_api.initial_admin_email == "admin@example.com"
        assert config.settings.admin_api.token_secret == "my-secret-key-long-enough"
        assert config.settings.admin_api.token_expiry_seconds == 3600
        assert config.settings.admin_api.password_length == 20

    def test_custom_settings(self, tmp_path):
        cfg_path = _write_config(
            tmp_path,
            _base_config(
                enabled=True,
                base_path="/mgmt",
                initial_admin_email="admin@example.com",
                token_secret="secret-long-enough-1234",
                token_expiry_seconds=7200,
                password_length=32,
            ),
        )
        config = AcmeehConfig(config_file=str(cfg_path), schema_file="bundled")
        assert config.settings.admin_api.base_path == "/mgmt"
        assert config.settings.admin_api.token_expiry_seconds == 7200
        assert config.settings.admin_api.password_length == 32
