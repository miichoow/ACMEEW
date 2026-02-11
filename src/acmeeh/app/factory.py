"""Flask application factory for ACMEEH.

Usage::

    from acmeeh.app import create_app
    from acmeeh.config import get_config
    from acmeeh.db import init_database

    db  = init_database(get_config().settings.database)
    app = create_app(config=get_config(), database=db)
"""

from __future__ import annotations

import atexit
import logging
import sys
from typing import TYPE_CHECKING

from flask import Flask, jsonify

if TYPE_CHECKING:
    from flask.typing import ResponseReturnValue
    from pypgkit import Database

    from acmeeh.config.acmeeh_config import AcmeehConfig

log = logging.getLogger(__name__)


def create_app(  # noqa: C901, PLR0915
    config: AcmeehConfig | None = None,
    database: Database | None = None,
) -> Flask:
    """Create and configure the ACMEEH Flask application.

    Parameters
    ----------
    config:
        Loaded :class:`AcmeehConfig`.  Falls back to :func:`get_config`
        when ``None``.
    database:
        Initialised :class:`Database` singleton.  When provided, the
        dependency container with all repositories is wired up.  When
        ``None`` the app still starts (useful for ``--validate-only``
        or testing) but repository access will raise at runtime.

    Returns
    -------
    Flask
        Fully configured WSGI application.

    """
    if config is None:
        from acmeeh.config import get_config  # noqa: PLC0415

        config = get_config()

    settings = config.settings

    app = Flask("acmeeh")
    app.config["ACMEEH_SETTINGS"] = settings
    app.config["ACMEEH_CONFIG"] = config
    app.config["MAX_CONTENT_LENGTH"] = settings.security.max_request_body_bytes

    # -- Rate limiter -------------------------------------------------------
    if settings.security.rate_limits.enabled:
        from acmeeh.app.rate_limiter import create_rate_limiter  # noqa: PLC0415

        app.extensions["rate_limiter"] = create_rate_limiter(
            settings.security.rate_limits,
            database,
        )

    # -- Graceful shutdown coordinator --------------------------------------
    from acmeeh.app.shutdown import ShutdownCoordinator  # noqa: PLC0415

    shutdown_coordinator = ShutdownCoordinator(
        graceful_timeout=settings.server.graceful_timeout,
    )
    app.extensions["shutdown_coordinator"] = shutdown_coordinator
    atexit.register(shutdown_coordinator.initiate)

    # -- WSGI middleware (outermost layer) -----------------------------------
    if settings.proxy.enabled:
        from acmeeh.app.middleware import TrustedProxyMiddleware  # noqa: PLC0415

        app.wsgi_app = TrustedProxyMiddleware(  # type: ignore[method-assign]
            app.wsgi_app,
            trusted_proxies=settings.proxy.trusted_proxies,
            for_header=settings.proxy.forwarded_for_header,
            proto_header=settings.proxy.forwarded_proto_header,
        )
        log.info(
            "Proxy middleware enabled (trusted: %s)",
            list(settings.proxy.trusted_proxies) or "all",
        )

    # -- Error handlers (RFC 7807) ------------------------------------------
    from acmeeh.app.errors import register_error_handlers  # noqa: PLC0415

    register_error_handlers(app)

    # -- Request lifecycle hooks --------------------------------------------
    from acmeeh.app.middleware import register_request_hooks  # noqa: PLC0415

    register_request_hooks(app)

    # -- Infrastructure endpoints -------------------------------------------
    _register_health(app)

    # -- Dependency container -----------------------------------------------
    if database is not None:
        from acmeeh.app.context import Container  # noqa: PLC0415

        container = Container(
            database,
            settings,
            shutdown_coordinator=shutdown_coordinator,
            rate_limiter=app.extensions.get("rate_limiter"),
        )
        app.extensions["container"] = container

        # -- Hook registry shutdown (process exit, not per-request) ---------
        atexit.register(container.hook_registry.shutdown)

        # -- Background challenge worker (optional) -------------------------
        if container.challenge_worker is not None:
            container.challenge_worker.start()
            atexit.register(container.challenge_worker.stop)

        # -- Cleanup worker -------------------------------------------------
        # Pass db-backed rate limiter if applicable
        from acmeeh.app.rate_limiter import DatabaseRateLimiter  # noqa: PLC0415
        from acmeeh.services.cleanup_worker import _CleanupTask  # noqa: PLC0415

        rate_limiter = app.extensions.get("rate_limiter")
        if isinstance(rate_limiter, DatabaseRateLimiter):
            gc_interval = settings.security.rate_limits.gc_interval_seconds
            container.cleanup_worker._tasks.append(  # noqa: SLF001
                _CleanupTask(
                    name="rate_limit_gc",
                    interval_seconds=gc_interval,
                    func=lambda: rate_limiter.gc(),  # type: ignore[arg-type]
                ),
            )
        container.cleanup_worker.start()
        atexit.register(container.cleanup_worker.stop)

        # Drain in-flight challenges on shutdown so clients can retry
        def _drain_on_shutdown() -> None:
            shutdown_coordinator.drain_processing_challenges(container.challenges)

        atexit.register(_drain_on_shutdown)

        # -- Expiration worker ----------------------------------------------
        container.expiration_worker.start()
        atexit.register(container.expiration_worker.stop)

        # -- ACME API routes ------------------------------------------------
        from acmeeh.api import register_blueprints  # noqa: PLC0415

        register_blueprints(app)

        # -- CRL endpoint (optional) ----------------------------------------
        # (registered inside register_blueprints if enabled)

        # -- Metrics endpoint (optional) ------------------------------------
        if settings.metrics.enabled:
            from acmeeh.api.metrics import metrics_bp  # noqa: PLC0415

            app.register_blueprint(
                metrics_bp,
                url_prefix=settings.metrics.path,
            )
            log.info("Metrics endpoint registered at %s", settings.metrics.path)

        # -- OCSP responder (optional) --------------------------------------
        if settings.ocsp.enabled and container.ocsp_service is not None:
            from acmeeh.api.ocsp import ocsp_bp  # noqa: PLC0415

            app.register_blueprint(
                ocsp_bp,
                url_prefix=settings.ocsp.path,
            )
            log.info("OCSP responder registered at %s", settings.ocsp.path)

        # -- Admin API (optional) -------------------------------------------
        if settings.admin_api.enabled and container.admin_service is not None:
            from acmeeh.admin.routes import admin_bp  # noqa: PLC0415

            app.register_blueprint(
                admin_bp,
                url_prefix=settings.admin_api.base_path.rstrip("/"),
            )
            log.info(
                "Admin API registered at %s",
                settings.admin_api.base_path,
            )

            # Bootstrap initial admin user
            pw = container.admin_service.bootstrap_admin(
                settings.admin_api.initial_admin_email,
            )
            if pw is not None:
                log.warning(
                    "Initial admin user created — password printed to stderr",
                )
                sys.stderr.write(
                    "\n"
                    "╔══════════════════════════════════════════════╗\n"
                    "║       INITIAL ADMIN USER CREATED             ║\n"
                    "║                                              ║\n"
                    f"║  Username: admin                             ║\n"
                    f"║  Password: {pw:<33s} ║\n"
                    "║                                              ║\n"
                    "║  Change this password immediately!           ║\n"
                    "╚══════════════════════════════════════════════╝\n"
                    "\n",
                )
                sys.stderr.flush()

    # -- Config hot-reload (SIGHUP) -----------------------------------------
    shutdown_coordinator.register_reload_signal()

    @app.before_request
    def _check_config_reload() -> None:
        """Reload safe config sections when SIGHUP is received."""
        sc = app.extensions.get("shutdown_coordinator")
        if sc is None or not sc.reload_requested:
            return

        try:
            cfg = app.config.get("ACMEEH_CONFIG")
            if cfg is None:
                sc.consume_reload()
                return

            new_settings = cfg.reload_settings()
            current = app.config["ACMEEH_SETTINGS"]
            reloaded = []

            # Only reload safe sections: logging level, rate_limits,
            # notifications, metrics toggle
            if new_settings.logging.level != current.logging.level:
                import logging as _logging  # noqa: PLC0415

                _logging.getLogger().setLevel(new_settings.logging.level)
                reloaded.append(f"logging.level={new_settings.logging.level}")

            if new_settings.security.rate_limits != current.security.rate_limits:
                reloaded.append("security.rate_limits")

            if new_settings.notifications != current.notifications:
                reloaded.append("notifications")

            if new_settings.metrics.enabled != current.metrics.enabled:
                reloaded.append(
                    f"metrics.enabled={new_settings.metrics.enabled}",
                )

            if reloaded:
                app.config["ACMEEH_SETTINGS"] = new_settings
                log.info(
                    "Config hot-reloaded sections: %s",
                    ", ".join(reloaded),
                )
            else:
                log.info(
                    "Config reload requested but no safe-to-reload changes detected",
                )
        except Exception:
            log.exception("Config hot-reload failed")
        finally:
            sc.consume_reload()

    log.info("Flask application created")
    return app


# ---------------------------------------------------------------------------
# Infrastructure endpoints
# ---------------------------------------------------------------------------


def _register_health(app: Flask) -> None:  # noqa: C901, PLR0915
    """Register ``/livez``, ``/healthz``, and ``/readyz`` probes."""
    from acmeeh import __version__  # noqa: PLC0415

    @app.route("/livez")
    def livez() -> ResponseReturnValue:
        """Return minimal liveness probe."""
        return jsonify({"alive": True, "version": __version__}), 200

    @app.route("/healthz")
    def healthz() -> ResponseReturnValue:  # noqa: C901, PLR0912, PLR0915
        """Return comprehensive health status."""
        result: dict = {"status": "ok", "version": __version__}
        checks: dict = {}

        container = app.extensions.get("container")
        if container is not None:
            settings = container.settings

            try:
                container.db.fetch_value("SELECT 1")
                checks["database"] = "connected"
            except Exception:  # noqa: BLE001
                checks["database"] = "disconnected"
                result["status"] = "degraded"

            # Connection pool stats
            try:
                pool = getattr(container.db, "_pool", None)
                if pool is not None and hasattr(pool, "get_stats"):
                    stats = pool.get_stats()
                    pool_info = {
                        "size": stats.get("pool_size", 0),
                        "available": stats.get("pool_available", 0),
                        "waiting": stats.get("requests_waiting", 0),
                        "min": stats.get("pool_min", 0),
                        "max": stats.get("pool_max", 0),
                    }
                    result["pool"] = pool_info
                    if pool_info["available"] == 0 and pool_info["waiting"] > 0:
                        result["status"] = "degraded"
            except Exception:  # noqa: BLE001
                log.debug("Failed to retrieve connection pool stats")

            # Shutdown coordinator status
            shutdown_coord = app.extensions.get("shutdown_coordinator")
            if shutdown_coord is not None:
                result["shutting_down"] = shutdown_coord.is_shutting_down

            if container.crl_manager is not None:
                crl_health = container.crl_manager.health_status()
                checks["crl"] = crl_health
                if crl_health.get("stale"):
                    result["status"] = "degraded"

            # Worker liveness
            workers_status: dict = {}
            if container.challenge_worker is not None:
                t = container.challenge_worker._thread  # noqa: SLF001
                alive = t is not None and t.is_alive()
                workers_status["challenge_worker"] = "alive" if alive else "dead"
                if not alive:
                    result["status"] = "degraded"

            t = getattr(container.cleanup_worker, "_thread", None)
            if t is not None:
                alive = t.is_alive()
                workers_status["cleanup_worker"] = "alive" if alive else "dead"
                if not alive:
                    result["status"] = "degraded"

            t = getattr(container.expiration_worker, "_thread", None)
            if t is not None:
                alive = t.is_alive()
                workers_status["expiration_worker"] = "alive" if alive else "dead"
                if not alive:
                    result["status"] = "degraded"

            if workers_status:
                result["workers"] = workers_status

            # CA backend status
            try:
                container.ca_backend.startup_check()
                checks["ca_backend"] = "ok"
            except Exception:  # noqa: BLE001
                checks["ca_backend"] = "error"
                result["status"] = "degraded"

            # SMTP connectivity (non-critical)
            if settings.smtp.enabled:
                try:
                    import smtplib  # noqa: PLC0415

                    with smtplib.SMTP(
                        settings.smtp.host,
                        settings.smtp.port,
                        timeout=5,
                    ) as s:
                        s.ehlo()
                    checks["smtp"] = "connected"
                except Exception:  # noqa: BLE001
                    checks["smtp"] = "unreachable"

            # DNS resolver reachability (non-critical)
            resolvers = settings.dns.resolvers or settings.challenges.dns01.resolvers
            if resolvers:
                try:
                    import socket  # noqa: PLC0415

                    socket.create_connection(
                        (resolvers[0], 53),
                        timeout=3,
                    ).close()
                    checks["dns_resolver"] = "reachable"
                except Exception:  # noqa: BLE001
                    checks["dns_resolver"] = "unreachable"

        if checks:
            result["checks"] = checks

        code = 200 if result["status"] == "ok" else 503
        return jsonify(result), code

    @app.route("/readyz")
    def readyz() -> ResponseReturnValue:
        """Return Kubernetes readiness probe."""
        container = app.extensions.get("container")
        if container is None:
            return (
                jsonify(
                    {"ready": False, "reason": "Container not initialized"},
                ),
                503,
            )

        # Check DB connectivity
        try:
            container.db.fetch_value("SELECT 1")
        except Exception:  # noqa: BLE001
            return (
                jsonify(
                    {"ready": False, "reason": "Database not connected"},
                ),
                503,
            )

        # Check CA backend
        try:
            container.ca_backend.startup_check()
        except Exception:  # noqa: BLE001
            return (
                jsonify(
                    {"ready": False, "reason": "CA backend not ready"},
                ),
                503,
            )

        # Check CRL freshness if enabled
        if container.crl_manager is not None:
            crl_health = container.crl_manager.health_status()
            if crl_health.get("stale"):
                return jsonify(
                    {
                        "ready": False,
                        "reason": "CRL is stale",
                        "crl": crl_health,
                    }
                ), 503

        return jsonify({"ready": True}), 200
