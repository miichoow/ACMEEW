"""Programmatic gunicorn runner for ACMEEH.

Starts gunicorn with settings derived from the ACMEEH config
rather than requiring a separate gunicorn config file.

Usage::

    from acmeeh.server.gunicorn_app import run_gunicorn

    run_gunicorn(flask_app, settings.server)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flask import Flask

    from acmeeh.config.settings import ServerSettings

log = logging.getLogger(__name__)


def run_gunicorn(app: Flask, settings: ServerSettings) -> None:
    """Start a gunicorn server from ACMEEH :class:`ServerSettings`.

    Raises :class:`RuntimeError` if gunicorn is not installed (e.g. on
    Windows).
    """
    try:
        from gunicorn.app.base import BaseApplication
    except ImportError:
        msg = (
            "gunicorn is not installed.  Install it with:\n"
            "    pip install gunicorn\n\n"
            "gunicorn only runs on Unix.  Use --dev for the Flask "
            "development server on Windows."
        )
        raise RuntimeError(
            msg,
        )

    class _App(BaseApplication):
        def __init__(self, flask_app: Flask, server: ServerSettings) -> None:
            self.application = flask_app
            self._server = server
            super().__init__()

        def load_config(self) -> None:
            s = self._server
            self.cfg.set("bind", f"{s.bind}:{s.port}")
            self.cfg.set("workers", s.workers)
            self.cfg.set("worker_class", s.worker_class)
            self.cfg.set("timeout", s.timeout)
            self.cfg.set("graceful_timeout", s.graceful_timeout)
            self.cfg.set("keepalive", s.keepalive)
            if s.max_requests:
                self.cfg.set("max_requests", s.max_requests)
            if s.max_requests_jitter:
                self.cfg.set("max_requests_jitter", s.max_requests_jitter)
            # Silence gunicorn's own access log — we handle it ourselves
            self.cfg.set("accesslog", None)

        def load(self) -> Flask:
            return self.application

    log.info(
        "Starting gunicorn — %s:%s (%d workers, %s)",
        settings.bind,
        settings.port,
        settings.workers,
        settings.worker_class,
    )
    _App(app, settings).run()
