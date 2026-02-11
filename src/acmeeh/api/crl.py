"""CRL distribution endpoint.

``GET /crl`` returns the current CRL in DER format.
"""

from __future__ import annotations

from flask import Blueprint, make_response

from acmeeh.app.context import get_container

crl_bp = Blueprint("crl", __name__)


@crl_bp.route("", methods=["GET"])
def get_crl():
    """Return the current CRL as DER-encoded ``application/pkix-crl``."""
    container = get_container()
    crl_manager = container.crl_manager
    if crl_manager is None:
        return {"error": "CRL not available"}, 404

    crl_bytes = crl_manager.get_crl()
    response = make_response(crl_bytes)
    response.headers["Content-Type"] = "application/pkix-crl"
    max_age = container.settings.crl.rebuild_interval_seconds
    response.headers["Cache-Control"] = f"public, max-age={max_age}"
    return response
