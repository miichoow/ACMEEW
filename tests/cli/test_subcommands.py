"""Tests for CLI subcommand parsing."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import yaml

from acmeeh.cli.main import _build_parser, main

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def parser():
    return _build_parser()


@pytest.fixture
def tmp_config(tmp_path):
    """Write a minimal config file and return its path."""
    config = {
        "server": {"external_url": "https://acme.test"},
        "database": {"database": "test", "user": "test"},
        "ca": {
            "internal": {
                "root_cert_path": "/tmp/test.crt",
                "root_key_path": "/tmp/test.key",
            },
        },
    }
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        yaml.safe_dump(config, default_flow_style=False, sort_keys=False), encoding="utf-8"
    )
    return str(cfg_path)


def _mock_config():
    """Create a mock AcmeehConfig with all needed settings."""
    mock_config = MagicMock()
    mock_settings = MagicMock()
    mock_settings.logging = MagicMock()
    mock_settings.server.external_url = "https://acme.test"
    mock_settings.server.bind = "0.0.0.0"
    mock_settings.server.port = 8443
    mock_settings.server.workers = 4
    mock_settings.database.user = "test"
    mock_settings.database.host = "localhost"
    mock_settings.database.port = 5432
    mock_settings.database.database = "test"
    mock_settings.ca.backend = "internal"
    mock_settings.challenges.enabled = ["http-01"]
    mock_settings.logging.level = "info"
    mock_settings.tos.require_agreement = False
    mock_settings.admin_api.enabled = False
    mock_config.settings = mock_settings
    return mock_config


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBackwardCompat:
    """Backward compat: --validate-only still works without subcommand."""

    def test_validate_only_flag_parsed(self, parser, tmp_config):
        args = parser.parse_args(["-c", tmp_config, "--validate-only"])
        assert args.validate_only is True
        assert args.command is None

    def test_dev_flag_parsed(self, parser, tmp_config):
        args = parser.parse_args(["-c", tmp_config, "--dev"])
        assert args.dev is True
        assert args.command is None

    def test_no_subcommand_defaults_to_serve(self, parser, tmp_config):
        args = parser.parse_args(["-c", tmp_config])
        assert args.command is None  # None means default serve behavior


class TestSubcommandParsing:
    """Each subcommand parses correctly."""

    def test_serve_subcommand(self, parser, tmp_config):
        args = parser.parse_args(["-c", tmp_config, "serve"])
        assert args.command == "serve"

    def test_serve_with_dev(self, parser, tmp_config):
        args = parser.parse_args(["-c", tmp_config, "serve", "--dev"])
        assert args.command == "serve"
        assert args.dev is True

    def test_db_status_subcommand(self, parser, tmp_config):
        args = parser.parse_args(["-c", tmp_config, "db", "status"])
        assert args.command == "db"
        assert args.db_command == "status"

    def test_db_migrate_subcommand(self, parser, tmp_config):
        args = parser.parse_args(["-c", tmp_config, "db", "migrate"])
        assert args.command == "db"
        assert args.db_command == "migrate"

    def test_ca_test_sign_subcommand(self, parser, tmp_config):
        args = parser.parse_args(["-c", tmp_config, "ca", "test-sign"])
        assert args.command == "ca"
        assert args.ca_command == "test-sign"

    def test_crl_rebuild_subcommand(self, parser, tmp_config):
        args = parser.parse_args(["-c", tmp_config, "crl", "rebuild"])
        assert args.command == "crl"
        assert args.crl_command == "rebuild"

    def test_admin_create_user_subcommand(self, parser, tmp_config):
        args = parser.parse_args(
            [
                "-c",
                tmp_config,
                "admin",
                "create-user",
                "--username",
                "testuser",
                "--email",
                "test@example.com",
            ]
        )
        assert args.command == "admin"
        assert args.admin_command == "create-user"
        assert args.username == "testuser"
        assert args.email == "test@example.com"

    def test_admin_create_user_with_role(self, parser, tmp_config):
        args = parser.parse_args(
            [
                "-c",
                tmp_config,
                "admin",
                "create-user",
                "--username",
                "testadmin",
                "--email",
                "admin@example.com",
                "--role",
                "admin",
            ]
        )
        assert args.role == "admin"

    def test_admin_create_user_default_role(self, parser, tmp_config):
        args = parser.parse_args(
            [
                "-c",
                tmp_config,
                "admin",
                "create-user",
                "--username",
                "u",
                "--email",
                "e@example.com",
            ]
        )
        assert args.role == "auditor"

    def test_debug_flag(self, parser, tmp_config):
        args = parser.parse_args(["-c", tmp_config, "--debug"])
        assert args.debug is True

    def test_config_is_required(self, parser):
        with pytest.raises(SystemExit):
            parser.parse_args([])


class TestServeSubcommand:
    """serve subcommand runs with mocked server."""

    def test_validate_only_exits_cleanly(self, tmp_config):
        """--validate-only should print success and exit 0."""
        mock_config = _mock_config()

        with (
            patch("acmeeh.config.acmeeh_config.AcmeehConfig", return_value=mock_config) as MockCls,
            patch("acmeeh.logging.configure_logging"),
            pytest.raises(SystemExit) as exc_info,
        ):
            # The singleton metaclass returns mock_config when called
            MockCls.return_value = mock_config
            main(["--config", tmp_config, "--validate-only"])

        assert exc_info.value.code == 0

    def test_missing_config_file_exits_1(self):
        """Non-existent config file should exit 1."""
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", "/nonexistent/path/config.yaml"])
        assert exc_info.value.code == 1

    def test_no_subcommand_without_dev_defaults_to_serve(self, parser, tmp_config):
        """No subcommand means default serve path."""
        args = parser.parse_args(["-c", tmp_config])
        # When no subcommand, command is None, and the code falls through to _run_serve
        assert args.command is None
        assert args.validate_only is False
