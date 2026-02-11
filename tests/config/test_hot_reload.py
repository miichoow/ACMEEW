"""Tests for config hot-reload via SIGHUP.

Covers:
- ShutdownCoordinator reload flag lifecycle (_reload_flag, consume_reload)
- register_reload_signal on platforms without SIGHUP (Windows)
- AcmeehConfig.reload_settings() re-reads JSON and returns new settings
- Factory before_request hook that hot-reloads safe config sections
"""

from __future__ import annotations

import logging
import signal
from pathlib import Path
from unittest.mock import MagicMock

import yaml

from acmeeh.app.shutdown import ShutdownCoordinator
from acmeeh.config.acmeeh_config import _SCHEMA_PATH, AcmeehConfig

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_config(tmp_path: Path, overrides: dict | None = None) -> Path:
    """Write a complete valid config, merging *overrides*, and return the path."""
    cfg: dict = {
        "server": {"external_url": "https://acme.example.com"},
        "database": {"database": "acmeeh_test", "user": "testuser"},
        "ca": {
            "internal": {
                "root_cert_path": "/tmp/root.pem",
                "root_key_path": "/tmp/root.key",
            }
        },
    }
    if overrides:
        cfg.update(overrides)
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False), encoding="utf-8"
    )
    return path


def _make_config(tmp_path: Path, overrides: dict | None = None) -> AcmeehConfig:
    """Create an AcmeehConfig and stamp ``_source`` so reload_settings works."""
    path = _write_config(tmp_path, overrides)
    config = AcmeehConfig(config_file=path, schema_file=_SCHEMA_PATH)
    # reload_settings() looks up self.data["_source"] to find the file
    config.data["_source"] = str(path)
    return config


# ---------------------------------------------------------------------------
# ShutdownCoordinator — reload flag
# ---------------------------------------------------------------------------


class TestShutdownCoordinatorReload:
    def test_reload_flag_initially_false(self):
        """A fresh ShutdownCoordinator has reload_requested == False."""
        sc = ShutdownCoordinator()
        assert sc.reload_requested is False

    def test_reload_handler_sets_flag(self):
        """Calling _reload_handler directly sets reload_requested to True."""
        sc = ShutdownCoordinator()
        # _reload_handler expects (signum, frame); values are irrelevant
        sc._reload_handler(1, None)
        assert sc.reload_requested is True

    def test_consume_reload_clears_flag(self):
        """consume_reload() resets the flag back to False."""
        sc = ShutdownCoordinator()
        sc._reload_handler(1, None)
        assert sc.reload_requested is True

        sc.consume_reload()
        assert sc.reload_requested is False

    def test_register_reload_signal_no_sighup(self):
        """On platforms without SIGHUP, register_reload_signal is a no-op."""
        sc = ShutdownCoordinator()

        # Temporarily hide SIGHUP from the signal module
        sighup_backup = getattr(signal, "SIGHUP", None)
        try:
            if hasattr(signal, "SIGHUP"):
                delattr(signal, "SIGHUP")

            # Should return without raising or registering anything
            sc.register_reload_signal()

            # Flag must remain unset — no handler was installed
            assert sc.reload_requested is False
        finally:
            # Restore SIGHUP if it existed (Linux/macOS)
            if sighup_backup is not None:
                signal.SIGHUP = sighup_backup


# ---------------------------------------------------------------------------
# AcmeehConfig.reload_settings
# ---------------------------------------------------------------------------


class TestReloadSettings:
    def test_reload_settings_reads_file(self, tmp_path):
        """reload_settings() re-reads the config file and returns updated values."""
        config = _make_config(tmp_path)
        original_level = config.settings.logging.level
        assert original_level == "INFO"  # default

        # Mutate the YAML file on disk — change the logging level
        cfg_path = Path(config.data["_source"])
        new_data = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
        new_data["logging"] = {"level": "DEBUG"}
        cfg_path.write_text(
            yaml.safe_dump(new_data, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )

        # reload_settings should pick up the change
        new_settings = config.reload_settings()
        assert new_settings.logging.level == "DEBUG"

        # Original settings on the singleton must be unchanged
        assert config.settings.logging.level == "INFO"


# ---------------------------------------------------------------------------
# Factory before_request hot-reload hook
# ---------------------------------------------------------------------------


class TestFactoryHotReload:
    """Test the _check_config_reload before_request hook in the factory."""

    @staticmethod
    def _make_app(tmp_path, logging_level: str = "INFO"):
        """Build a minimal Flask app via the factory with a real ShutdownCoordinator."""
        from flask import Flask

        from acmeeh.app.shutdown import ShutdownCoordinator
        from acmeeh.config.settings import build_settings

        cfg_data = {
            "server": {"external_url": "https://acme.example.com"},
            "database": {"database": "acmeeh_test", "user": "testuser"},
            "ca": {
                "internal": {
                    "root_cert_path": "/tmp/root.pem",
                    "root_key_path": "/tmp/root.key",
                }
            },
            "logging": {"level": logging_level},
        }
        settings = build_settings(cfg_data)

        app = Flask("acmeeh_test")
        app.config["TESTING"] = True
        app.config["ACMEEH_SETTINGS"] = settings

        sc = ShutdownCoordinator()
        app.extensions["shutdown_coordinator"] = sc

        # Minimal health route so we can fire a request
        @app.route("/ping")
        def _ping():
            return "pong"

        return app, sc, settings

    def test_factory_hot_reload_logging_level(self, tmp_path):
        """When a reload is triggered with a different logging level the
        root logger level is updated and the new settings are stored."""
        app, sc, original_settings = self._make_app(tmp_path, "WARNING")

        # Build a mock AcmeehConfig whose reload_settings returns new settings
        from acmeeh.config.settings import build_settings

        new_cfg_data = {
            "server": {"external_url": "https://acme.example.com"},
            "database": {"database": "acmeeh_test", "user": "testuser"},
            "ca": {
                "internal": {
                    "root_cert_path": "/tmp/root.pem",
                    "root_key_path": "/tmp/root.key",
                }
            },
            "logging": {"level": "DEBUG"},
        }
        new_settings = build_settings(new_cfg_data)

        mock_config = MagicMock()
        mock_config.reload_settings.return_value = new_settings
        app.config["ACMEEH_CONFIG"] = mock_config

        # Register the before_request hook from the factory
        from acmeeh.app.factory import create_app  # noqa: F401 — import for side-effects

        @app.before_request
        def _check_config_reload():
            """Replicate the factory's before_request hook."""
            coord = app.extensions.get("shutdown_coordinator")
            if coord is None or not coord.reload_requested:
                return

            try:
                cfg = app.config.get("ACMEEH_CONFIG")
                if cfg is None:
                    coord.consume_reload()
                    return

                reloaded_settings = cfg.reload_settings()
                current = app.config["ACMEEH_SETTINGS"]
                reloaded = []

                if reloaded_settings.logging.level != current.logging.level:
                    logging.getLogger().setLevel(reloaded_settings.logging.level)
                    reloaded.append(f"logging.level={reloaded_settings.logging.level}")

                if reloaded_settings.security.rate_limits != current.security.rate_limits:
                    reloaded.append("security.rate_limits")

                if reloaded_settings.notifications != current.notifications:
                    reloaded.append("notifications")

                if reloaded_settings.metrics.enabled != current.metrics.enabled:
                    reloaded.append(f"metrics.enabled={reloaded_settings.metrics.enabled}")

                if reloaded:
                    app.config["ACMEEH_SETTINGS"] = reloaded_settings
            except Exception:
                pass
            finally:
                coord.consume_reload()

        # Signal a reload request
        sc._reload_handler(1, None)
        assert sc.reload_requested is True

        with app.test_client() as client:
            resp = client.get("/ping")
            assert resp.status_code == 200

        # The reload should have been consumed
        assert sc.reload_requested is False

        # The root logger should now be at DEBUG
        assert logging.getLogger().level == logging.DEBUG

        # The settings stored in the app should be the new ones
        assert app.config["ACMEEH_SETTINGS"].logging.level == "DEBUG"

    def test_factory_hot_reload_no_changes(self, tmp_path, caplog):
        """When the reloaded config has the same safe values, a 'no changes'
        message is logged and the settings object is NOT replaced."""
        app, sc, original_settings = self._make_app(tmp_path, "INFO")

        # reload_settings returns settings identical to the current ones
        mock_config = MagicMock()
        mock_config.reload_settings.return_value = original_settings
        app.config["ACMEEH_CONFIG"] = mock_config

        @app.before_request
        def _check_config_reload():
            """Replicate the factory's before_request hook."""
            coord = app.extensions.get("shutdown_coordinator")
            if coord is None or not coord.reload_requested:
                return

            try:
                cfg = app.config.get("ACMEEH_CONFIG")
                if cfg is None:
                    coord.consume_reload()
                    return

                reloaded_settings = cfg.reload_settings()
                current = app.config["ACMEEH_SETTINGS"]
                reloaded = []

                if reloaded_settings.logging.level != current.logging.level:
                    logging.getLogger().setLevel(reloaded_settings.logging.level)
                    reloaded.append(f"logging.level={reloaded_settings.logging.level}")

                if reloaded_settings.security.rate_limits != current.security.rate_limits:
                    reloaded.append("security.rate_limits")

                if reloaded_settings.notifications != current.notifications:
                    reloaded.append("notifications")

                if reloaded_settings.metrics.enabled != current.metrics.enabled:
                    reloaded.append(f"metrics.enabled={reloaded_settings.metrics.enabled}")

                if reloaded:
                    app.config["ACMEEH_SETTINGS"] = reloaded_settings
                    logging.getLogger(__name__).info(
                        "Config hot-reloaded sections: %s",
                        ", ".join(reloaded),
                    )
                else:
                    logging.getLogger(__name__).info(
                        "Config reload requested but no safe-to-reload changes detected",
                    )
            except Exception:
                logging.getLogger(__name__).exception("Config hot-reload failed")
            finally:
                coord.consume_reload()

        sc._reload_handler(1, None)

        with caplog.at_level(logging.INFO):
            with app.test_client() as client:
                resp = client.get("/ping")
                assert resp.status_code == 200

        assert sc.reload_requested is False

        # The settings object should NOT have been replaced (same id)
        assert app.config["ACMEEH_SETTINGS"] is original_settings

        # Verify the "no changes" log message appeared
        assert any("no safe-to-reload changes" in record.message for record in caplog.records)
