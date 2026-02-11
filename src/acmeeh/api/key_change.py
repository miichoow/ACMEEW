"""ACME key change endpoint (RFC 8555 §7.3.5).

``POST /key-change`` — account key rollover via nested JWS.

The outer JWS is authenticated with the OLD key (kid).
The outer payload is the INNER JWS (a complete JWS object).
The inner JWS is signed with the NEW key (jwk in protected header).
The inner payload contains ``{"account": "...", "oldKey": {...}}``.
"""

from __future__ import annotations

import json
import logging

from flask import Blueprint, g, jsonify

from acmeeh.api.decorators import require_jws
from acmeeh.api.serializers import serialize_account
from acmeeh.app.context import get_container
from acmeeh.app.errors import MALFORMED, AcmeProblem
from acmeeh.core.jws import (
    JWSObject,
    _b64url_decode,
    jwk_to_public_key,
    verify_signature,
)

log = logging.getLogger(__name__)

key_change_bp = Blueprint("key_change", __name__)


def _parse_inner_jws(payload: dict) -> JWSObject:
    """Parse the inner JWS from the outer payload dict.

    The outer payload (already decoded as JSON by ``@require_jws``)
    must contain ``protected``, ``payload``, and ``signature`` fields
    forming a valid JWS Flattened Serialization.
    """
    for field in ("protected", "payload", "signature"):
        if field not in payload:
            raise AcmeProblem(
                MALFORMED,
                f"Key change outer payload (inner JWS) missing '{field}'",
            )

    try:
        protected_bytes = _b64url_decode(payload["protected"])
        protected_header = json.loads(protected_bytes)
    except Exception as exc:
        raise AcmeProblem(
            MALFORMED,
            f"Cannot decode inner JWS protected header: {exc}",
        )

    inner_payload = None
    payload_b64 = payload["payload"]
    if payload_b64:
        try:
            inner_payload = json.loads(_b64url_decode(payload_b64))
        except Exception as exc:
            raise AcmeProblem(
                MALFORMED,
                f"Cannot decode inner JWS payload: {exc}",
            )

    try:
        signature = _b64url_decode(payload["signature"])
    except Exception as exc:
        raise AcmeProblem(
            MALFORMED,
            f"Cannot decode inner JWS signature: {exc}",
        )

    return JWSObject(
        protected_header=protected_header,
        protected_b64=payload["protected"],
        payload=inner_payload,
        payload_b64=payload_b64,
        signature=signature,
        signature_b64=payload["signature"],
    )


@key_change_bp.route("/key-change", methods=["POST"], endpoint="key_change")
@require_jws(use_kid=True)
def key_change():
    """POST /key-change — account key rollover (RFC 8555 §7.3.5).

    Outer JWS: signed with OLD key (kid auth via @require_jws).
    Outer payload: the inner JWS (protected + payload + signature).
    Inner JWS: signed with NEW key (jwk in protected header).
    Inner payload: {"account": "<url>", "oldKey": {<jwk>}}.
    """
    container = get_container()
    payload = g.payload

    if not payload or not isinstance(payload, dict):
        raise AcmeProblem(MALFORMED, "Key change request body cannot be empty")

    # 1. Parse inner JWS from outer payload
    inner_jws = _parse_inner_jws(payload)

    # 2. Inner protected header must have "jwk" (the new key)
    new_jwk = inner_jws.protected_header.get("jwk")
    if not new_jwk:
        raise AcmeProblem(
            MALFORMED,
            "Inner JWS protected header must contain 'jwk' (the new key)",
        )

    # 3. Inner "alg" must be present
    if not inner_jws.protected_header.get("alg"):
        raise AcmeProblem(
            MALFORMED,
            "Inner JWS protected header must contain 'alg'",
        )

    # 4. Inner "url" must match key-change URL
    inner_url = inner_jws.protected_header.get("url")
    expected_url = container.urls.key_change
    if inner_url != expected_url:
        raise AcmeProblem(
            MALFORMED,
            f"Inner JWS 'url' ({inner_url}) does not match key-change URL ({expected_url})",
        )

    # 5. Verify inner JWS signature with the new key
    new_public_key = jwk_to_public_key(new_jwk)
    verify_signature(inner_jws, new_public_key)

    # 6. Parse inner payload: {"account": "...", "oldKey": {...}}
    inner_payload = inner_jws.payload
    if not inner_payload or not isinstance(inner_payload, dict):
        raise AcmeProblem(
            MALFORMED,
            "Inner JWS payload must be a JSON object with 'account' and 'oldKey'",
        )

    account_url = inner_payload.get("account")
    old_key = inner_payload.get("oldKey")

    if not account_url:
        raise AcmeProblem(
            MALFORMED,
            "Inner key change payload missing 'account'",
        )
    if not old_key:
        raise AcmeProblem(
            MALFORMED,
            "Inner key change payload missing 'oldKey'",
        )

    # 7. Validate account URL matches the authenticated account
    expected_account_url = container.urls.account_url(g.account.id)
    if account_url != expected_account_url:
        raise AcmeProblem(
            MALFORMED,
            "Inner key change 'account' does not match authenticated account",
        )

    # 8. Perform the key rollover
    account = container.key_change_service.rollover(
        account_id=g.account.id,
        old_jwk=old_key,
        new_jwk=new_jwk,
    )

    contacts = container.account_contacts.find_by_account(account.id)
    body = serialize_account(account, contacts, container.urls)
    response = jsonify(body)
    response.headers["Location"] = container.urls.account_url(account.id)
    return response
