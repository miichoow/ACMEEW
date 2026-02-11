"""Tests for HSM configuration: schema, settings, and cross-field validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from jsonschema import ValidationError, validate

from acmeeh.config.acmeeh_config import AcmeehConfig, ConfigValidationError
from acmeeh.config.settings import HsmSettings, build_settings

SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent.parent / "src" / "acmeeh" / "config" / "schema.json"
)


@pytest.fixture(scope="module")
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _minimal_config(**ca_overrides) -> dict:
    """Return a minimal valid config with HSM backend."""
    ca = {
        "backend": "hsm",
        "hsm": {
            "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so",
            "token_label": "ACMEEH-CA",
            "pin": "1234",
            "key_label": "ca-signing-key",
            "issuer_cert_path": "/etc/acmeeh/ca-cert.pem",
        },
    }
    ca.update(ca_overrides)
    return {
        "server": {"external_url": "https://acme.example.com"},
        "database": {"database": "acmeeh", "user": "acmeeh"},
        "ca": ca,
    }


# ---------------------------------------------------------------------------
# JSON Schema tests
# ---------------------------------------------------------------------------


class TestSchemaValidation:
    def test_valid_hsm_config(self, schema):
        cfg = _minimal_config()
        validate(instance=cfg, schema=schema)

    def test_full_hsm_config(self, schema):
        cfg = _minimal_config(
            hsm={
                "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so",
                "token_label": "ACMEEH-CA",
                "slot_id": 0,
                "pin": "1234",
                "key_label": "ca-signing-key",
                "key_id": "0102030405",
                "key_type": "ec",
                "hash_algorithm": "sha384",
                "issuer_cert_path": "/etc/acmeeh/ca-cert.pem",
                "chain_path": "/etc/acmeeh/ca-chain.pem",
                "serial_source": "random",
                "login_required": True,
                "session_pool_size": 8,
            }
        )
        validate(instance=cfg, schema=schema)

    def test_invalid_key_type(self, schema):
        cfg = _minimal_config(
            hsm={
                "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so",
                "token_label": "ACMEEH-CA",
                "pin": "1234",
                "key_label": "ca-signing-key",
                "issuer_cert_path": "/etc/acmeeh/ca-cert.pem",
                "key_type": "dsa",
            }
        )
        with pytest.raises(ValidationError):
            validate(instance=cfg, schema=schema)

    def test_invalid_hash_algorithm(self, schema):
        cfg = _minimal_config(
            hsm={
                "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so",
                "token_label": "ACMEEH-CA",
                "pin": "1234",
                "key_label": "ca-signing-key",
                "issuer_cert_path": "/etc/acmeeh/ca-cert.pem",
                "hash_algorithm": "md5",
            }
        )
        with pytest.raises(ValidationError):
            validate(instance=cfg, schema=schema)

    def test_invalid_serial_source(self, schema):
        cfg = _minimal_config(
            hsm={
                "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so",
                "token_label": "ACMEEH-CA",
                "pin": "1234",
                "key_label": "ca-signing-key",
                "issuer_cert_path": "/etc/acmeeh/ca-cert.pem",
                "serial_source": "hsm",
            }
        )
        with pytest.raises(ValidationError):
            validate(instance=cfg, schema=schema)

    def test_session_pool_size_minimum(self, schema):
        cfg = _minimal_config(
            hsm={
                "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so",
                "token_label": "ACMEEH-CA",
                "pin": "1234",
                "key_label": "ca-signing-key",
                "issuer_cert_path": "/etc/acmeeh/ca-cert.pem",
                "session_pool_size": 0,
            }
        )
        with pytest.raises(ValidationError, match="minimum"):
            validate(instance=cfg, schema=schema)

    def test_session_pool_size_maximum(self, schema):
        cfg = _minimal_config(
            hsm={
                "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so",
                "token_label": "ACMEEH-CA",
                "pin": "1234",
                "key_label": "ca-signing-key",
                "issuer_cert_path": "/etc/acmeeh/ca-cert.pem",
                "session_pool_size": 64,
            }
        )
        with pytest.raises(ValidationError, match="maximum"):
            validate(instance=cfg, schema=schema)

    def test_no_additional_properties(self, schema):
        cfg = _minimal_config(
            hsm={
                "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so",
                "token_label": "ACMEEH-CA",
                "pin": "1234",
                "key_label": "ca-signing-key",
                "issuer_cert_path": "/etc/acmeeh/ca-cert.pem",
                "unknown_field": True,
            }
        )
        with pytest.raises(ValidationError, match="additionalProperties"):
            validate(instance=cfg, schema=schema)

    def test_rsa_key_type_valid(self, schema):
        cfg = _minimal_config(
            hsm={
                "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so",
                "token_label": "ACMEEH-CA",
                "pin": "1234",
                "key_label": "ca-signing-key",
                "issuer_cert_path": "/etc/acmeeh/ca-cert.pem",
                "key_type": "rsa",
            }
        )
        validate(instance=cfg, schema=schema)


# ---------------------------------------------------------------------------
# Settings dataclass tests
# ---------------------------------------------------------------------------


class TestSettingsBuilding:
    def test_build_hsm_settings_defaults(self):
        data = {
            "server": {"external_url": "https://acme.example.com"},
            "database": {"database": "acmeeh", "user": "acmeeh"},
            "ca": {},
        }
        settings = build_settings(data)
        hsm = settings.ca.hsm

        assert isinstance(hsm, HsmSettings)
        assert hsm.pkcs11_library == ""
        assert hsm.token_label is None
        assert hsm.slot_id is None
        assert hsm.pin == ""
        assert hsm.key_label is None
        assert hsm.key_id is None
        assert hsm.key_type == "ec"
        assert hsm.hash_algorithm == "sha256"
        assert hsm.issuer_cert_path == ""
        assert hsm.chain_path is None
        assert hsm.serial_source == "database"
        assert hsm.login_required is True
        assert hsm.session_pool_size == 4
        assert hsm.session_pool_timeout_seconds == 30

    def test_build_hsm_settings_custom(self):
        data = {
            "server": {"external_url": "https://acme.example.com"},
            "database": {"database": "acmeeh", "user": "acmeeh"},
            "ca": {
                "hsm": {
                    "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so",
                    "token_label": "ACMEEH-CA",
                    "slot_id": 5,
                    "pin": "secret",
                    "key_label": "my-key",
                    "key_id": "aabb",
                    "key_type": "rsa",
                    "hash_algorithm": "sha512",
                    "issuer_cert_path": "/etc/ca.pem",
                    "chain_path": "/etc/chain.pem",
                    "serial_source": "random",
                    "login_required": False,
                    "session_pool_size": 16,
                }
            },
        }
        settings = build_settings(data)
        hsm = settings.ca.hsm

        assert hsm.pkcs11_library == "/usr/lib/softhsm/libsofthsm2.so"
        assert hsm.token_label == "ACMEEH-CA"
        assert hsm.slot_id == 5
        assert hsm.pin == "secret"
        assert hsm.key_label == "my-key"
        assert hsm.key_id == "aabb"
        assert hsm.key_type == "rsa"
        assert hsm.hash_algorithm == "sha512"
        assert hsm.issuer_cert_path == "/etc/ca.pem"
        assert hsm.chain_path == "/etc/chain.pem"
        assert hsm.serial_source == "random"
        assert hsm.login_required is False
        assert hsm.session_pool_size == 16

    def test_hsm_settings_frozen(self):
        data = {
            "server": {"external_url": "https://acme.example.com"},
            "database": {"database": "acmeeh", "user": "acmeeh"},
            "ca": {},
        }
        settings = build_settings(data)
        hsm = settings.ca.hsm

        with pytest.raises(AttributeError):
            hsm.pkcs11_library = "changed"


# ---------------------------------------------------------------------------
# Cross-field validation (additional_checks) tests
# ---------------------------------------------------------------------------


class TestAdditionalChecks:
    def test_hsm_backend_valid(self, tmp_path):
        cfg = _minimal_config()
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(
            yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )
        config = AcmeehConfig(config_file=str(cfg_path), schema_file="unused")
        assert config.settings.ca.backend == "hsm"

    def test_hsm_missing_pkcs11_library(self, tmp_path):
        cfg = _minimal_config(
            hsm={
                "pkcs11_library": "",
                "token_label": "ACMEEH-CA",
                "pin": "1234",
                "key_label": "ca-signing-key",
                "issuer_cert_path": "/etc/ca.pem",
            }
        )
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(
            yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )
        with pytest.raises(ConfigValidationError, match="pkcs11_library"):
            AcmeehConfig(config_file=str(cfg_path), schema_file="unused")

    def test_hsm_missing_token_and_slot(self, tmp_path):
        cfg = _minimal_config(
            hsm={
                "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so",
                "pin": "1234",
                "key_label": "ca-signing-key",
                "issuer_cert_path": "/etc/ca.pem",
            }
        )
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(
            yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )
        with pytest.raises(ConfigValidationError, match="token_label.*slot_id"):
            AcmeehConfig(config_file=str(cfg_path), schema_file="unused")

    def test_hsm_slot_id_alone_is_valid(self, tmp_path):
        cfg = _minimal_config(
            hsm={
                "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so",
                "slot_id": 0,
                "pin": "1234",
                "key_label": "ca-signing-key",
                "issuer_cert_path": "/etc/ca.pem",
            }
        )
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(
            yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )
        config = AcmeehConfig(config_file=str(cfg_path), schema_file="unused")
        assert config.settings.ca.hsm.slot_id == 0

    def test_hsm_missing_key_label_and_key_id(self, tmp_path):
        cfg = _minimal_config(
            hsm={
                "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so",
                "token_label": "ACMEEH-CA",
                "pin": "1234",
                "issuer_cert_path": "/etc/ca.pem",
            }
        )
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(
            yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )
        with pytest.raises(ConfigValidationError, match="key_label.*key_id"):
            AcmeehConfig(config_file=str(cfg_path), schema_file="unused")

    def test_hsm_key_id_alone_is_valid(self, tmp_path):
        cfg = _minimal_config(
            hsm={
                "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so",
                "token_label": "ACMEEH-CA",
                "pin": "1234",
                "key_id": "0102",
                "issuer_cert_path": "/etc/ca.pem",
            }
        )
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(
            yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )
        config = AcmeehConfig(config_file=str(cfg_path), schema_file="unused")
        assert config.settings.ca.hsm.key_id == "0102"

    def test_hsm_missing_issuer_cert_path(self, tmp_path):
        cfg = _minimal_config(
            hsm={
                "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so",
                "token_label": "ACMEEH-CA",
                "pin": "1234",
                "key_label": "ca-signing-key",
                "issuer_cert_path": "",
            }
        )
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(
            yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )
        with pytest.raises(ConfigValidationError, match="issuer_cert_path"):
            AcmeehConfig(config_file=str(cfg_path), schema_file="unused")

    def test_hsm_missing_pin_when_login_required(self, tmp_path):
        cfg = _minimal_config(
            hsm={
                "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so",
                "token_label": "ACMEEH-CA",
                "pin": "",
                "key_label": "ca-signing-key",
                "issuer_cert_path": "/etc/ca.pem",
                "login_required": True,
            }
        )
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(
            yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )
        with pytest.raises(ConfigValidationError, match="pin"):
            AcmeehConfig(config_file=str(cfg_path), schema_file="unused")

    def test_hsm_no_pin_when_login_not_required(self, tmp_path):
        cfg = _minimal_config(
            hsm={
                "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so",
                "token_label": "ACMEEH-CA",
                "pin": "",
                "key_label": "ca-signing-key",
                "issuer_cert_path": "/etc/ca.pem",
                "login_required": False,
            }
        )
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(
            yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )
        config = AcmeehConfig(config_file=str(cfg_path), schema_file="unused")
        assert config.settings.ca.hsm.login_required is False

    def test_hsm_all_missing_collects_all_errors(self, tmp_path):
        cfg = _minimal_config(
            hsm={
                "pkcs11_library": "",
                "pin": "",
                "issuer_cert_path": "",
                "login_required": True,
            }
        )
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(
            yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )
        with pytest.raises(ConfigValidationError) as exc_info:
            AcmeehConfig(config_file=str(cfg_path), schema_file="unused")
        errors = exc_info.value.errors
        assert len(errors) == 5
        assert any("pkcs11_library" in e for e in errors)
        assert any("token_label" in e for e in errors)
        assert any("key_label" in e for e in errors)
        assert any("issuer_cert_path" in e for e in errors)
        assert any("pin" in e for e in errors)
