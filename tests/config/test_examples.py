"""Tests that validate all example configuration files.

Each example YAML in ``examples/`` (and the root ``acmeeh.example.yaml``)
must pass schema validation and cross-field checks when required
environment variables are provided with dummy values.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from acmeeh.config.acmeeh_config import _SCHEMA_PATH, AcmeehConfig, ConfigValidationError

# Root of the project (tests/config/test_examples.py -> tests/config -> tests -> root)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Matches ${VAR} and ${VAR:-default} — group(1) is the var name,
# group(2) is the default (None when there is no :- part).
_ENV_REF_RE = re.compile(r"\$\{([^}:]+?)(?::-(.*))?\}")


def _find_example_files() -> list[Path]:
    """Collect all YAML example config files."""
    examples_dir = _PROJECT_ROOT / "examples"
    files = sorted(examples_dir.glob("*.yaml"))
    root_example = _PROJECT_ROOT / "acmeeh.example.yaml"
    if root_example.exists():
        files.append(root_example)
    return files


def _extract_required_env_vars(path: Path) -> set[str]:
    """Return env var names referenced as ``${VAR}`` (no default) in *path*."""
    text = path.read_text(encoding="utf-8")
    required: set[str] = set()
    for match in _ENV_REF_RE.finditer(text):
        var_name = match.group(1)
        has_default = match.group(2) is not None
        if not has_default:
            required.add(var_name)
    return required


_EXAMPLE_FILES = _find_example_files()
_EXAMPLE_IDS = [f.stem for f in _EXAMPLE_FILES]


# ---------------------------------------------------------------------------
# YAML structure tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("example_path", _EXAMPLE_FILES, ids=_EXAMPLE_IDS)
class TestExampleYAMLStructure:
    """Verify each example is valid YAML with required top-level sections."""

    def test_valid_yaml(self, example_path: Path):
        """Example must parse as a YAML dict."""
        text = example_path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
        assert isinstance(data, dict), f"{example_path.name} did not parse to a dict"

    def test_has_required_sections(self, example_path: Path):
        """Example must contain server, database, and ca sections."""
        data = yaml.safe_load(example_path.read_text(encoding="utf-8"))
        assert "server" in data, f"{example_path.name} missing 'server'"
        assert "database" in data, f"{example_path.name} missing 'database'"
        assert "ca" in data, f"{example_path.name} missing 'ca'"

    def test_external_url_no_trailing_slash(self, example_path: Path):
        """server.external_url must not end with '/'."""
        data = yaml.safe_load(example_path.read_text(encoding="utf-8"))
        url = data.get("server", {}).get("external_url", "")
        # Resolve env-var references to a dummy URL for the check
        if url.startswith("${"):
            return  # env-var placeholder — can't validate statically
        assert not url.endswith("/"), f"{example_path.name}: server.external_url ends with '/'"


# ---------------------------------------------------------------------------
# Full config loading (schema + cross-field validation)
# ---------------------------------------------------------------------------


# Dummy value long enough for token_secret (>= 16 chars) and non-empty for
# all other env var uses (passwords, PINs, tokens, etc.)
_DUMMY_ENV_VALUE = "test-dummy-value-1234567890"


@pytest.mark.parametrize("example_path", _EXAMPLE_FILES, ids=_EXAMPLE_IDS)
def test_example_config_loads_successfully(
    example_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """Each example config must load without errors when env vars are set."""
    required_vars = _extract_required_env_vars(example_path)
    for var in required_vars:
        monkeypatch.setenv(var, _DUMMY_ENV_VALUE)

    config = AcmeehConfig(config_file=example_path, schema_file=_SCHEMA_PATH)

    assert config.settings is not None
    assert config.settings.server.external_url


_EXAMPLES_WITH_REQUIRED_ENV = [f for f in _EXAMPLE_FILES if _extract_required_env_vars(f)]
_EXAMPLES_WITH_REQUIRED_ENV_IDS = [f.stem for f in _EXAMPLES_WITH_REQUIRED_ENV]


@pytest.mark.parametrize(
    "example_path",
    _EXAMPLES_WITH_REQUIRED_ENV,
    ids=_EXAMPLES_WITH_REQUIRED_ENV_IDS,
)
def test_example_config_fails_without_required_env_vars(
    example_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """Examples with required env vars must fail clearly when vars are unset."""
    required_vars = _extract_required_env_vars(example_path)

    for var in required_vars:
        monkeypatch.delenv(var, raising=False)

    with pytest.raises(ConfigValidationError, match="Environment variable"):
        AcmeehConfig(config_file=example_path, schema_file=_SCHEMA_PATH)
