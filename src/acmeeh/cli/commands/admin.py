"""Admin user management subcommands."""

from __future__ import annotations

import logging
import sys

log = logging.getLogger(__name__)


def run_admin(config, args) -> None:
    """Handle admin subcommands."""
    if args.admin_command == "create-user":
        _create_user(config, args)
    else:
        sys.exit(1)


def _create_user(config, args) -> None:
    """Create a new admin user."""
    if not config.settings.admin_api.enabled:
        sys.exit(1)

    username = args.username
    email = args.email
    role = args.role or "auditor"

    if not username or not email:
        sys.exit(1)

    from acmeeh.app import create_app
    from acmeeh.core.types import AdminRole
    from acmeeh.db import init_database

    try:
        admin_role = AdminRole(role)
    except ValueError:
        sys.exit(1)

    db = init_database(config.settings.database)
    app = create_app(config=config, database=db)

    with app.app_context():
        from acmeeh.app.context import get_container

        container = get_container()
        if container.admin_service is None:
            sys.exit(1)

        _user, _password = container.admin_service.create_user(
            username,
            email,
            admin_role,
        )
