"""ACME nonce endpoints (RFC 8555 §7.2).

``HEAD /new-nonce`` — returns 200 with ``Replay-Nonce`` header.
``GET  /new-nonce`` — returns 204 with ``Replay-Nonce`` header.

Both responses include a fresh nonce via the ``add_acme_headers``
after-request hook; these routes just set the correct status code.
"""

from __future__ import annotations

from flask import Blueprint, make_response

nonce_bp = Blueprint("nonce", __name__)


@nonce_bp.route("", methods=["HEAD"])
def head_new_nonce():
    """HEAD /new-nonce — 200 with Replay-Nonce."""
    response = make_response("", 200)
    response.headers["Cache-Control"] = "no-store"
    return response


@nonce_bp.route("", methods=["GET"])
def get_new_nonce():
    """GET /new-nonce — 204 with Replay-Nonce."""
    response = make_response("", 204)
    response.headers["Cache-Control"] = "no-store"
    return response
