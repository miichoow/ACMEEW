"""OCSP responder endpoint.

POST /ocsp — submit DER OCSP request in body
GET /ocsp/<encoded> — submit base64url-encoded OCSP request in URL
"""

from __future__ import annotations

import base64
import logging

from flask import Blueprint, make_response, request

from acmeeh.app.context import get_container
from acmeeh.app.errors import AcmeProblem

log = logging.getLogger(__name__)

ocsp_bp = Blueprint("ocsp", __name__)

_OCSP_CONTENT_TYPE = "application/ocsp-response"


@ocsp_bp.route("", methods=["POST"])
def ocsp_post():
    """POST /ocsp — process a DER-encoded OCSP request."""
    container = get_container()

    if not hasattr(container, "ocsp_service") or container.ocsp_service is None:
        msg = "about:blank"
        raise AcmeProblem(msg, "OCSP is not enabled", status=503)

    ocsp_request_der = request.get_data()
    if not ocsp_request_der:
        msg = "about:blank"
        raise AcmeProblem(msg, "Empty OCSP request body", status=400)

    response_der = container.ocsp_service.handle_request(ocsp_request_der)

    resp = make_response(response_der)
    resp.headers["Content-Type"] = _OCSP_CONTENT_TYPE
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@ocsp_bp.route("/<path:encoded>", methods=["GET"])
def ocsp_get(encoded: str):
    """GET /ocsp/<encoded> — process a base64url-encoded OCSP request."""
    container = get_container()

    if not hasattr(container, "ocsp_service") or container.ocsp_service is None:
        msg = "about:blank"
        raise AcmeProblem(msg, "OCSP is not enabled", status=503)

    try:
        # URL-safe base64 decode
        ocsp_request_der = base64.urlsafe_b64decode(encoded + "==")
    except Exception:
        msg = "about:blank"
        raise AcmeProblem(msg, "Invalid base64 encoding", status=400)

    response_der = container.ocsp_service.handle_request(ocsp_request_der)

    resp = make_response(response_der)
    resp.headers["Content-Type"] = _OCSP_CONTENT_TYPE
    resp.headers["Cache-Control"] = "no-cache"
    return resp
