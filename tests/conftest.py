"""Root conftest for the ACMEEH test suite."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# Make ``src/`` importable without installing the package
# ---------------------------------------------------------------------------
_SRC = str(Path(__file__).resolve().parent.parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


# ---------------------------------------------------------------------------
# Minimal config data shared by multiple test modules
# ---------------------------------------------------------------------------


@pytest.fixture()
def minimal_config_data() -> dict:
    """Return a dict containing the minimum required config fields."""
    return {
        "server": {"external_url": "https://acme.example.com"},
        "database": {"database": "acmeeh_test", "user": "testuser"},
        "ca": {
            "internal": {
                "root_cert_path": "/tmp/root.pem",
                "root_key_path": "/tmp/root.key",
            }
        },
    }


@pytest.fixture()
def tmp_config_file(tmp_path: Path, minimal_config_data: dict) -> Path:
    """Write *minimal_config_data* to a temp YAML file and return its path."""
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        yaml.safe_dump(minimal_config_data, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )
    return cfg


# ---------------------------------------------------------------------------
# ConfigKit singleton cleanup — autouse so every test gets a fresh slate
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def fresh_config():
    """Reset the AcmeehConfig singleton before and after every test."""
    try:
        from acmeeh.config.acmeeh_config import AcmeehConfig

        AcmeehConfig.reset()
    except Exception:
        pass
    yield
    try:
        from acmeeh.config.acmeeh_config import AcmeehConfig

        AcmeehConfig.reset()
    except Exception:
        pass
