"""Admin API Flask blueprint."""

from __future__ import annotations

import json as _json
import logging
from typing import TYPE_CHECKING, Any

from flask import Blueprint, Response, current_app, g, jsonify, request

from acmeeh.admin.auth import (
    get_login_limiter,
    get_token_blacklist,
    require_admin_auth,
    require_role,
)
from acmeeh.admin.pagination import (
    build_link_header,
    decode_cursor,
    encode_cursor,
)
from acmeeh.admin.serializers import (
    serialize_admin_user,
    serialize_allowed_identifier,
    serialize_audit_log,
    serialize_certificate,
    serialize_csr_profile,
    serialize_eab_credential,
    serialize_login_response,
    serialize_notification,
)
from acmeeh.app.context import get_container
from acmeeh.app.errors import AcmeProblem
from acmeeh.core.types import AdminRole, RevocationReason
from acmeeh.logging import security_events

if TYPE_CHECKING:
    from collections.abc import Iterator
    from uuid import UUID

    from flask.typing import ResponseReturnValue

    from acmeeh.admin.service import AdminUserService

log = logging.getLogger(__name__)

admin_bp = Blueprint("admin_api", __name__)


def _get_admin_service() -> AdminUserService:
    """Return the admin service, raising 503 if admin is not enabled."""
    svc = get_container().admin_service
    if svc is None:
        raise AcmeProblem(
            "about:blank",
            "Admin API is not enabled",
            status=503,
        )
    return svc


@admin_bp.route("/auth/login", methods=["POST"])
def login() -> ResponseReturnValue:
    """Authenticate and return a bearer token."""
    data = request.get_json(silent=True)
    if not data:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Request body must be JSON",
            status=400,
        )

    username = data.get("username", "")
    password = data.get("password", "")
    if not username or not password:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Both 'username' and 'password' are required",
            status=400,
        )

    limiter = get_login_limiter()
    rate_key = f"{request.remote_addr}:{username}"
    limiter.check(rate_key)

    container = get_container()
    try:
        user, token = _get_admin_service().authenticate(
            username,
            password,
            ip_address=request.remote_addr,
        )
    except AcmeProblem:
        limiter.record_failure(rate_key)
        raise
    limiter.record_success(rate_key)
    return jsonify(serialize_login_response(user, token))


@admin_bp.route("/auth/logout", methods=["POST"])
@require_admin_auth
def logout() -> ResponseReturnValue:
    """Revoke the current bearer token."""
    token = request.headers.get("Authorization", "")[7:]
    get_token_blacklist().revoke_token(token)
    return jsonify({"status": "logged_out"}), 200


@admin_bp.route("/users", methods=["GET"])
@require_admin_auth
@require_role("admin", "auditor")
def list_users() -> ResponseReturnValue:
    """List all admin users."""
    container = get_container()
    users = _get_admin_service().list_users()
    return jsonify([serialize_admin_user(u) for u in users])


@admin_bp.route("/users", methods=["POST"])
@require_admin_auth
@require_role("admin")
def create_user() -> ResponseReturnValue:
    """Create a new admin user."""
    data = request.get_json(silent=True)
    if not data:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Request body must be JSON",
            status=400,
        )

    username = data.get("username", "")
    email = data.get("email", "")
    role_str = data.get("role", "auditor")

    if not username or not email:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Both 'username' and 'email' are required",
            status=400,
        )

    try:
        role = AdminRole(role_str)
    except ValueError:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            f"Invalid role '{role_str}'. Must be 'admin' or 'auditor'",
            status=400,
        ) from None

    container = get_container()
    user, password = _get_admin_service().create_user(
        username,
        email,
        role,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )

    resp = serialize_admin_user(user)
    resp["password"] = password
    return jsonify(resp), 201


@admin_bp.route("/users/<uuid:user_id>", methods=["GET"])
@require_admin_auth
@require_role("admin", "auditor")
def get_user(user_id: UUID) -> ResponseReturnValue:
    """Get a specific admin user."""
    container = get_container()
    user = _get_admin_service().get_user(user_id)
    return jsonify(serialize_admin_user(user))


@admin_bp.route("/users/<uuid:user_id>", methods=["PATCH"])
@require_admin_auth
@require_role("admin")
def update_user(user_id: UUID) -> ResponseReturnValue:
    """Update an admin user (enable/disable, role change)."""
    data = request.get_json(silent=True)
    if not data:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Request body must be JSON",
            status=400,
        )

    kwargs: dict[str, Any] = {}
    if "enabled" in data:
        kwargs["enabled"] = bool(data["enabled"])
    if "role" in data:
        try:
            kwargs["role"] = AdminRole(data["role"])
        except ValueError:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                f"Invalid role '{data['role']}'. Must be 'admin' or 'auditor'",
                status=400,
            ) from None

    container = get_container()
    user = _get_admin_service().update_user(
        user_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
        **kwargs,
    )
    return jsonify(serialize_admin_user(user))


@admin_bp.route("/users/<uuid:user_id>", methods=["DELETE"])
@require_admin_auth
@require_role("admin")
def delete_user(user_id: UUID) -> ResponseReturnValue:
    """Delete an admin user."""
    container = get_container()
    _get_admin_service().delete_user(
        user_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return "", 204


@admin_bp.route("/me", methods=["GET"])
@require_admin_auth
@require_role("admin", "auditor")
def get_me() -> ResponseReturnValue:
    """Get the current user's profile."""
    return jsonify(serialize_admin_user(g.admin_user))


@admin_bp.route("/me/reset-password", methods=["POST"])
@require_admin_auth
@require_role("admin", "auditor")
def reset_own_password() -> ResponseReturnValue:
    """Reset the current user's password."""
    container = get_container()
    user, password = _get_admin_service().reset_password(
        g.admin_user.id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    resp = serialize_admin_user(user)
    resp["password"] = password
    return jsonify(resp)


@admin_bp.route("/audit-log", methods=["GET"])
@require_admin_auth
@require_role("admin")
def get_audit_log() -> ResponseReturnValue:
    """View the admin audit log with optional filters.

    Supports cursor-based pagination via ``?cursor=...&limit=...``.
    Falls back to offset-based for backward compatibility.
    """
    container = get_container()
    page_settings = container.settings.admin_api
    limit = request.args.get(
        "limit",
        page_settings.default_page_size,
        type=int,
    )
    limit = min(limit, page_settings.max_page_size)

    filters = {}
    for key in ("action", "user_id", "since", "until"):
        val = request.args.get(key)
        if val:
            filters[key] = val

    cursor_param = request.args.get("cursor")
    cursor_id = None
    if cursor_param:
        try:
            cursor_id = decode_cursor(cursor_param)
        except ValueError:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                "Invalid cursor parameter",
                status=400,
            ) from None

    if filters:
        entries = _get_admin_service().search_audit_log(
            filters,
            limit + 1,
        )
    else:
        entries = _get_admin_service().get_audit_log(limit + 1)

    # Apply cursor filter (repos don't natively support cursor)
    if cursor_id is not None:
        entries = [e for e in entries if e.id < cursor_id]

    has_next = len(entries) > limit
    entries = entries[:limit]

    data = [serialize_audit_log(e) for e in entries]
    response = jsonify(data)

    if has_next and entries:
        next_cursor = encode_cursor(entries[-1].id)
        link = build_link_header(
            request.base_url,
            next_cursor,
            limit,
        )
        if link:
            response.headers["Link"] = link
    return response


# -------------------------------------------------------------------
# EAB credential management
# -------------------------------------------------------------------


@admin_bp.route("/eab", methods=["GET"])
@require_admin_auth
@require_role("admin")
def list_eab() -> ResponseReturnValue:
    """List all EAB credentials."""
    container = get_container()
    creds = _get_admin_service().list_eab()
    return jsonify([serialize_eab_credential(c) for c in creds])


@admin_bp.route("/eab", methods=["POST"])
@require_admin_auth
@require_role("admin")
def create_eab() -> ResponseReturnValue:
    """Create an EAB credential.

    Kid is provided, HMAC key is generated.
    """
    data = request.get_json(silent=True)
    if not data:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Request body must be JSON",
            status=400,
        )

    kid = data.get("kid", "")
    if not kid:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "'kid' is required",
            status=400,
        )

    label = data.get("label", "")

    container = get_container()
    cred = _get_admin_service().create_eab(
        kid,
        label=label,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )

    return jsonify(
        serialize_eab_credential(cred, include_hmac=True),
    ), 201


@admin_bp.route("/eab/<uuid:cred_id>", methods=["GET"])
@require_admin_auth
@require_role("admin")
def get_eab(cred_id: UUID) -> ResponseReturnValue:
    """Get a specific EAB credential."""
    container = get_container()
    cred = _get_admin_service().get_eab(cred_id)
    return jsonify(serialize_eab_credential(cred))


@admin_bp.route("/eab/<uuid:cred_id>/revoke", methods=["POST"])
@require_admin_auth
@require_role("admin")
def revoke_eab(cred_id: UUID) -> ResponseReturnValue:
    """Revoke an EAB credential."""
    container = get_container()
    cred = _get_admin_service().revoke_eab(
        cred_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return jsonify(serialize_eab_credential(cred))


# -------------------------------------------------------------------
# Allowed identifier management
# -------------------------------------------------------------------


@admin_bp.route("/allowed-identifiers", methods=["GET"])
@require_admin_auth
@require_role("admin")
def list_allowed_identifiers() -> ResponseReturnValue:
    """List all allowed identifiers with associated accounts."""
    container = get_container()
    items = _get_admin_service().list_allowed_identifiers()
    return jsonify([serialize_allowed_identifier(ident, acct_ids) for ident, acct_ids in items])


@admin_bp.route("/allowed-identifiers", methods=["POST"])
@require_admin_auth
@require_role("admin")
def create_allowed_identifier() -> ResponseReturnValue:
    """Create a new allowed identifier."""
    data = request.get_json(silent=True)
    if not data:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Request body must be JSON",
            status=400,
        )

    id_type = data.get("type", "")
    id_value = data.get("value", "")
    if not id_type or not id_value:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Both 'type' and 'value' are required",
            status=400,
        )

    container = get_container()
    ident = _get_admin_service().create_allowed_identifier(
        id_type,
        id_value,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return jsonify(serialize_allowed_identifier(ident)), 201


@admin_bp.route(
    "/allowed-identifiers/<uuid:identifier_id>",
    methods=["GET"],
)
@require_admin_auth
@require_role("admin")
def get_allowed_identifier(
    identifier_id: UUID,
) -> ResponseReturnValue:
    """Get an allowed identifier with its associated accounts."""
    container = get_container()
    ident, acct_ids = _get_admin_service().get_allowed_identifier(identifier_id)
    return jsonify(serialize_allowed_identifier(ident, acct_ids))


@admin_bp.route(
    "/allowed-identifiers/<uuid:identifier_id>",
    methods=["DELETE"],
)
@require_admin_auth
@require_role("admin")
def delete_allowed_identifier(
    identifier_id: UUID,
) -> ResponseReturnValue:
    """Delete an allowed identifier (cascades associations)."""
    container = get_container()
    _get_admin_service().delete_allowed_identifier(
        identifier_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return "", 204


@admin_bp.route(
    "/allowed-identifiers/<uuid:identifier_id>/accounts/<uuid:account_id>",
    methods=["PUT"],
)
@require_admin_auth
@require_role("admin")
def add_identifier_account(
    identifier_id: UUID,
    account_id: UUID,
) -> ResponseReturnValue:
    """Associate an allowed identifier with an ACME account."""
    container = get_container()
    _get_admin_service().add_identifier_account(
        identifier_id,
        account_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return "", 204


@admin_bp.route(
    "/allowed-identifiers/<uuid:identifier_id>/accounts/<uuid:account_id>",
    methods=["DELETE"],
)
@require_admin_auth
@require_role("admin")
def remove_identifier_account(
    identifier_id: UUID,
    account_id: UUID,
) -> ResponseReturnValue:
    """Remove an identifier-account association."""
    container = get_container()
    _get_admin_service().remove_identifier_account(
        identifier_id,
        account_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return "", 204


@admin_bp.route(
    "/accounts/<uuid:account_id>/allowed-identifiers",
    methods=["GET"],
)
@require_admin_auth
@require_role("admin")
def list_account_identifiers(
    account_id: UUID,
) -> ResponseReturnValue:
    """List allowed identifiers for a specific ACME account."""
    container = get_container()
    idents = _get_admin_service().list_account_identifiers(
        account_id,
    )
    return jsonify([serialize_allowed_identifier(i) for i in idents])


# -------------------------------------------------------------------
# CRL management
# -------------------------------------------------------------------


@admin_bp.route("/crl/rebuild", methods=["POST"])
@require_admin_auth
@require_role("admin")
def rebuild_crl() -> ResponseReturnValue:
    """Force a CRL rebuild."""
    container = get_container()
    if container.crl_manager is None:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "CRL is not enabled",
            status=503,
        )
    container.crl_manager.force_rebuild()

    _get_admin_service()._log_action(  # noqa: SLF001
        g.admin_user.id,
        "crl_rebuild",
        ip_address=request.remote_addr,
    )

    return jsonify(container.crl_manager.health_status())


# -------------------------------------------------------------------
# CSR profile management
# -------------------------------------------------------------------


@admin_bp.route("/csr-profiles", methods=["GET"])
@require_admin_auth
@require_role("admin", "auditor")
def list_csr_profiles() -> ResponseReturnValue:
    """List all CSR profiles."""
    container = get_container()
    profiles = _get_admin_service().list_csr_profiles()
    return jsonify([serialize_csr_profile(p) for p in profiles])


@admin_bp.route("/csr-profiles", methods=["POST"])
@require_admin_auth
@require_role("admin")
def create_csr_profile() -> ResponseReturnValue:
    """Create a new CSR profile."""
    data = request.get_json(silent=True)
    if not data:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Request body must be JSON",
            status=400,
        )

    name = data.get("name", "")
    if not name:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "'name' is required",
            status=400,
        )

    profile_data = data.get("profile_data")
    if profile_data is None:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "'profile_data' is required",
            status=400,
        )

    description = data.get("description", "")

    container = get_container()
    profile = _get_admin_service().create_csr_profile(
        name,
        profile_data,
        description=description,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return jsonify(serialize_csr_profile(profile)), 201


@admin_bp.route(
    "/csr-profiles/<uuid:profile_id>/validate",
    methods=["POST"],
)
@require_admin_auth
@require_role("admin", "auditor")
def validate_csr_profile(
    profile_id: UUID,
) -> ResponseReturnValue:
    """Dry-run validate a CSR against a profile without issuing."""
    data = request.get_json(silent=True)
    if not data:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Request body must be JSON",
            status=400,
        )

    csr_b64 = data.get("csr", "")
    if not csr_b64:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "'csr' (base64-DER) is required",
            status=400,
        )

    container = get_container()
    result = _get_admin_service().validate_csr(
        profile_id,
        csr_b64,
    )
    return jsonify(result)


@admin_bp.route(
    "/csr-profiles/<uuid:profile_id>",
    methods=["GET"],
)
@require_admin_auth
@require_role("admin", "auditor")
def get_csr_profile(
    profile_id: UUID,
) -> ResponseReturnValue:
    """Get a specific CSR profile with associated accounts."""
    container = get_container()
    profile, account_ids = _get_admin_service().get_csr_profile(profile_id)
    return jsonify(serialize_csr_profile(profile, account_ids))


@admin_bp.route(
    "/csr-profiles/<uuid:profile_id>",
    methods=["PUT"],
)
@require_admin_auth
@require_role("admin")
def update_csr_profile(
    profile_id: UUID,
) -> ResponseReturnValue:
    """Update a CSR profile (full replacement)."""
    data = request.get_json(silent=True)
    if not data:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Request body must be JSON",
            status=400,
        )

    name = data.get("name", "")
    if not name:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "'name' is required",
            status=400,
        )

    profile_data = data.get("profile_data")
    if profile_data is None:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "'profile_data' is required",
            status=400,
        )

    description = data.get("description", "")

    container = get_container()
    profile = _get_admin_service().update_csr_profile(
        profile_id,
        name,
        profile_data,
        description=description,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return jsonify(serialize_csr_profile(profile))


@admin_bp.route(
    "/csr-profiles/<uuid:profile_id>",
    methods=["DELETE"],
)
@require_admin_auth
@require_role("admin")
def delete_csr_profile(
    profile_id: UUID,
) -> ResponseReturnValue:
    """Delete a CSR profile."""
    container = get_container()
    _get_admin_service().delete_csr_profile(
        profile_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return "", 204


@admin_bp.route(
    "/csr-profiles/<uuid:profile_id>/accounts/<uuid:account_id>",
    methods=["PUT"],
)
@require_admin_auth
@require_role("admin")
def assign_profile_account(
    profile_id: UUID,
    account_id: UUID,
) -> ResponseReturnValue:
    """Assign a CSR profile to an ACME account."""
    container = get_container()
    _get_admin_service().assign_profile_to_account(
        profile_id,
        account_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return "", 204


@admin_bp.route(
    "/csr-profiles/<uuid:profile_id>/accounts/<uuid:account_id>",
    methods=["DELETE"],
)
@require_admin_auth
@require_role("admin")
def unassign_profile_account(
    profile_id: UUID,
    account_id: UUID,
) -> ResponseReturnValue:
    """Remove a CSR profile assignment from an account."""
    container = get_container()
    _get_admin_service().unassign_profile_from_account(
        profile_id,
        account_id,
        actor_id=g.admin_user.id,
        ip_address=request.remote_addr,
    )
    return "", 204


@admin_bp.route(
    "/accounts/<uuid:account_id>/csr-profile",
    methods=["GET"],
)
@require_admin_auth
@require_role("admin", "auditor")
def get_account_csr_profile(
    account_id: UUID,
) -> ResponseReturnValue:
    """Get the CSR profile assigned to an ACME account."""
    container = get_container()
    profile = _get_admin_service().get_account_csr_profile(
        account_id,
    )
    if profile is None:
        return jsonify(None)
    return jsonify(serialize_csr_profile(profile))


# -------------------------------------------------------------------
# Notification management
# -------------------------------------------------------------------


@admin_bp.route("/notifications", methods=["GET"])
@require_admin_auth
@require_role("admin")
def list_notifications() -> ResponseReturnValue:
    """List notifications with optional filters and pagination."""
    container = get_container()
    page_settings = container.settings.admin_api
    status = request.args.get("status")
    limit = request.args.get(
        "limit",
        page_settings.default_page_size,
        type=int,
    )
    offset = request.args.get("offset", 0, type=int)
    limit = min(limit, page_settings.max_page_size)
    notifications = _get_admin_service().list_notifications(
        status,
        limit + 1,
        offset,
    )

    has_next = len(notifications) > limit
    notifications = notifications[:limit]

    data = [serialize_notification(n) for n in notifications]
    response = jsonify(data)

    if has_next and notifications:
        next_cursor = encode_cursor(notifications[-1].id)
        link = build_link_header(
            request.base_url,
            next_cursor,
            limit,
        )
        if link:
            response.headers["Link"] = link
    return response


@admin_bp.route("/notifications/retry", methods=["POST"])
@require_admin_auth
@require_role("admin")
def retry_notifications() -> ResponseReturnValue:
    """Retry failed notifications."""
    container = get_container()
    count = _get_admin_service().retry_failed_notifications()

    _get_admin_service()._log_action(  # noqa: SLF001
        g.admin_user.id,
        "retry_notifications",
        details={"count": count},
        ip_address=request.remote_addr,
    )

    return jsonify({"retried": count})


@admin_bp.route("/notifications/purge", methods=["POST"])
@require_admin_auth
@require_role("admin")
def purge_notifications() -> ResponseReturnValue:
    """Purge old sent notifications."""
    data = request.get_json(silent=True) or {}
    days = data.get("days", 30)
    if not isinstance(days, int) or days < 1:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "'days' must be a positive integer",
            status=400,
        )

    container = get_container()
    count = _get_admin_service().purge_notifications(days)

    _get_admin_service()._log_action(  # noqa: SLF001
        g.admin_user.id,
        "purge_notifications",
        details={"days": days, "count": count},
        ip_address=request.remote_addr,
    )

    return jsonify({"purged": count})


# -------------------------------------------------------------------
# Certificate search & inventory
# -------------------------------------------------------------------


@admin_bp.route("/certificates", methods=["GET"])
@require_admin_auth
@require_role("admin", "auditor")
def search_certificates() -> ResponseReturnValue:
    """Search certificates with filters and pagination."""
    container = get_container()
    page_settings = container.settings.admin_api
    filters = {}
    for key in (
        "account_id",
        "serial",
        "fingerprint",
        "status",
        "domain",
        "expiring_before",
    ):
        val = request.args.get(key)
        if val:
            filters[key] = val

    limit = request.args.get(
        "limit",
        page_settings.default_page_size,
        type=int,
    )
    offset = request.args.get("offset", 0, type=int)
    limit = min(limit, page_settings.max_page_size)

    certs = _get_admin_service().search_certificates(
        filters,
        limit + 1,
        offset,
    )

    has_next = len(certs) > limit
    certs = certs[:limit]

    data = [serialize_certificate(c) for c in certs]
    response = jsonify(data)

    if has_next and certs:
        next_cursor = encode_cursor(certs[-1].id)
        link = build_link_header(
            request.base_url,
            next_cursor,
            limit,
        )
        if link:
            response.headers["Link"] = link
    return response


@admin_bp.route("/certificates/<serial>", methods=["GET"])
@require_admin_auth
@require_role("admin", "auditor")
def get_certificate_by_serial(
    serial: str,
) -> ResponseReturnValue:
    """Get a certificate by serial number."""
    container = get_container()
    cert = _get_admin_service().get_certificate_by_serial(
        serial,
    )
    return jsonify(serialize_certificate(cert))


@admin_bp.route(
    "/certificates/by-fingerprint/<fingerprint>",
    methods=["GET"],
)
@require_admin_auth
@require_role("admin", "auditor")
def get_certificate_by_fingerprint(
    fingerprint: str,
) -> ResponseReturnValue:
    """Get a certificate by its SHA-256 fingerprint (hex)."""
    container = get_container()
    cert = container.certificates.find_by_fingerprint(
        fingerprint,
    )
    if cert is None:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            f"Certificate with fingerprint '{fingerprint}' not found",
            status=404,
        )
    return jsonify(serialize_certificate(cert))


# -------------------------------------------------------------------
# Audit log export & enhanced search
# -------------------------------------------------------------------


@admin_bp.route("/audit-log/export", methods=["POST"])
@require_admin_auth
@require_role("admin")
def export_audit_log() -> ResponseReturnValue:
    """Export audit log as NDJSON."""
    data = request.get_json(silent=True) or {}
    filters = {}
    for key in ("action", "user_id", "since", "until"):
        if key in data:
            filters[key] = data[key]

    container = get_container()
    export_limit = container.settings.admin_api.max_page_size * 10
    entries = _get_admin_service().search_audit_log(
        filters,
        limit=export_limit,
    )

    def generate() -> Iterator[str]:
        for entry in entries:
            yield (_json.dumps(serialize_audit_log(entry)) + "\n")

    _get_admin_service()._log_action(  # noqa: SLF001
        g.admin_user.id,
        "export_audit_log",
        details={
            "filters": filters,
            "count": len(entries),
        },
        ip_address=request.remote_addr,
    )

    return Response(
        generate(),
        mimetype="application/x-ndjson",
    )


# -------------------------------------------------------------------
# Maintenance mode
# -------------------------------------------------------------------


@admin_bp.route("/maintenance", methods=["GET"])
@require_admin_auth
@require_role("admin")
def get_maintenance_status() -> ResponseReturnValue:
    """Get current maintenance mode status."""
    shutdown_coord = current_app.extensions.get(
        "shutdown_coordinator",
    )
    enabled = shutdown_coord.maintenance_mode if shutdown_coord else False
    return jsonify({"maintenance_mode": enabled})


@admin_bp.route("/maintenance", methods=["POST"])
@require_admin_auth
@require_role("admin")
def set_maintenance_mode() -> ResponseReturnValue:
    """Enable or disable maintenance mode.

    Body: ``{"enabled": true}`` or ``{"enabled": false}``.
    """
    data = request.get_json(silent=True)
    if not data or "enabled" not in data:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Request body must include 'enabled' (boolean)",
            status=400,
        )

    enabled = bool(data["enabled"])
    shutdown_coord = current_app.extensions.get(
        "shutdown_coordinator",
    )
    if shutdown_coord is None:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Shutdown coordinator not available",
            status=500,
        )

    shutdown_coord.set_maintenance(enabled)
    security_events.maintenance_mode_changed(
        enabled,
        g.admin_user.username,
    )

    container = get_container()
    _get_admin_service()._log_action(  # noqa: SLF001
        g.admin_user.id,
        "maintenance_mode",
        details={"enabled": enabled},
        ip_address=request.remote_addr,
    )

    return jsonify({"maintenance_mode": enabled})


# -------------------------------------------------------------------
# Bulk certificate revocation
# -------------------------------------------------------------------


@admin_bp.route(
    "/certificates/bulk-revoke",
    methods=["POST"],
)
@require_admin_auth
@require_role("admin")
def bulk_revoke_certificates() -> ResponseReturnValue:  # noqa: C901
    """Revoke multiple certificates matching a filter.

    Body::

        {
            "filter": {
                "account_id": "...",
                "serial_numbers": [...],
                "domain": "...",
                "issued_before": "...",
                "issued_after": "...",
            },
            "reason": 4,
            "dry_run": false
        }
    """
    data = request.get_json(silent=True)
    if not data or "filter" not in data:
        msg = "about:blank"
        raise AcmeProblem(
            msg,
            "Request body must include 'filter' object",
            status=400,
        )

    filt = data["filter"]
    reason_code = data.get("reason")
    dry_run = data.get("dry_run", False)

    rev_reason = None
    if reason_code is not None:
        try:
            rev_reason = RevocationReason(reason_code)
        except ValueError:
            msg = "about:blank"
            raise AcmeProblem(
                msg,
                f"Invalid revocation reason code: {reason_code}",
                status=400,
            ) from None

    container = get_container()
    cert_repo = container.certificates

    # Build query filters for certificate search
    search_filters: dict[str, str] = {}
    if "account_id" in filt:
        search_filters["account_id"] = filt["account_id"]
    if "domain" in filt:
        search_filters["domain"] = filt["domain"]
    if "issued_before" in filt:
        search_filters["expiring_before"] = filt["issued_before"]
    if "status" not in search_filters:
        search_filters["status"] = "active"

    # Get matching certificates
    certs = _get_admin_service().search_certificates(
        search_filters,
        limit=10000,
        offset=0,
    )

    # Apply serial number filter if specified
    if "serial_numbers" in filt:
        serial_set = set(filt["serial_numbers"])
        certs = [c for c in certs if c.serial_number in serial_set]

    # Filter out already-revoked certificates
    certs = [c for c in certs if getattr(c, "revoked_at", None) is None]

    if dry_run:
        return jsonify(
            {
                "dry_run": True,
                "matching_certificates": len(certs),
                "serial_numbers": [c.serial_number for c in certs[:100]],
            }
        )

    # Perform revocation
    revoked_count = 0
    errors = []
    for cert in certs:
        try:
            result = cert_repo.revoke(cert.id, rev_reason)
            if result is not None:
                revoked_count += 1
        except Exception as exc:  # noqa: BLE001
            errors.append(
                {
                    "serial_number": cert.serial_number,
                    "error": str(exc),
                }
            )

    filter_desc = ", ".join(f"{k}={v}" for k, v in filt.items())
    reason_name = rev_reason.name if rev_reason else "unspecified"
    security_events.bulk_revocation(
        g.admin_user.username,
        revoked_count,
        reason=reason_name,
        filter_desc=filter_desc,
    )

    _get_admin_service()._log_action(  # noqa: SLF001
        g.admin_user.id,
        "bulk_revoke",
        details={
            "filter": filt,
            "reason": reason_name,
            "revoked": revoked_count,
            "errors": len(errors),
        },
        ip_address=request.remote_addr,
    )

    return jsonify(
        {
            "revoked": revoked_count,
            "errors": errors[:50] if errors else [],
            "total_matched": len(certs),
        }
    )
