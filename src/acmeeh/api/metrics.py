"""Prometheus-compatible metrics endpoint.

``GET /metrics`` returns metrics in text format.
Optionally protected by admin API bearer token auth when
``metrics.auth_required`` is ``true`` in the configuration.
"""

from __future__ import annotations

from flask import Blueprint, current_app, make_response, request

from acmeeh.app.context import get_container
from acmeeh.app.errors import AcmeProblem

metrics_bp = Blueprint("metrics", __name__)


def _check_metrics_auth() -> None:
    """Enforce admin bearer token auth if metrics.auth_required is set."""
    settings = current_app.config.get("ACMEEH_SETTINGS")
    if settings is None or not settings.metrics.auth_required:
        return

    if not settings.admin_api.enabled:
        return

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        msg = "urn:acmeeh:admin:error:unauthorized"
        raise AcmeProblem(
            msg,
            "Metrics endpoint requires authentication",
            status=401,
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_header[7:]

    from acmeeh.admin.auth import decode_token, get_token_blacklist

    if get_token_blacklist().is_revoked(token):
        msg = "urn:acmeeh:admin:error:unauthorized"
        raise AcmeProblem(
            msg,
            "Token has been revoked",
            status=401,
        )

    payload = decode_token(
        token,
        settings.admin_api.token_secret,
        settings.admin_api.token_expiry_seconds,
    )
    if payload is None:
        msg = "urn:acmeeh:admin:error:unauthorized"
        raise AcmeProblem(
            msg,
            "Invalid or expired token",
            status=401,
        )


@metrics_bp.route("", methods=["GET"])
def get_metrics():
    """Return metrics in Prometheus text exposition format."""
    _check_metrics_auth()

    container = get_container()
    collector = container.metrics_collector
    if collector is None:
        return "# No metrics available\n", 200, {"Content-Type": "text/plain"}

    body = collector.export()
    response = make_response(body)
    response.headers["Content-Type"] = "text/plain; version=0.0.4; charset=utf-8"
    return response
