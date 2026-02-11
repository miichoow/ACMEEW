"""ACME directory endpoint (RFC 8555 §7.1.1).

``GET /directory`` — returns resource URLs and server metadata.
This is the only ACME endpoint that does not require JWS authentication.
"""

from __future__ import annotations

from flask import Blueprint, jsonify

from acmeeh.api.serializers import serialize_directory
from acmeeh.app.context import get_container

directory_bp = Blueprint("directory", __name__)


@directory_bp.route("", methods=["GET"])
def get_directory():
    """Return the ACME directory resource."""
    container = get_container()
    body = serialize_directory(container.urls, container.settings)
    return jsonify(body), 200
