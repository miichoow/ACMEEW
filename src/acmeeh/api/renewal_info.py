"""ACME Renewal Information endpoint (draft-ietf-acme-ari).

GET /renewalInfo/<certID>
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify, make_response

from acmeeh.app.context import get_container
from acmeeh.app.errors import MALFORMED, AcmeProblem

log = logging.getLogger(__name__)

renewal_info_bp = Blueprint("renewal_info", __name__)


@renewal_info_bp.route("/<path:cert_id>", methods=["GET"])
def get_renewal_info(cert_id: str):
    """GET /renewalInfo/<certID> -- get renewal information."""
    container = get_container()

    if not hasattr(container, "renewal_info_service") or container.renewal_info_service is None:
        msg = "about:blank"
        raise AcmeProblem(msg, "ARI is not enabled", status=503)

    info = container.renewal_info_service.get_renewal_info(cert_id)
    if info is None:
        raise AcmeProblem(MALFORMED, "Certificate not found", status=404)

    retry_after = info.pop("retryAfter", 3600)

    response = make_response(jsonify(info))
    response.headers["Retry-After"] = str(retry_after)
    return response
