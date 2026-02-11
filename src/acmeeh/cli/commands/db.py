"""Database management subcommands."""

from __future__ import annotations

import logging
import sys

log = logging.getLogger(__name__)


def run_db(config, args) -> None:
    """Handle db subcommands."""
    if args.db_command == "status":
        _db_status(config)
    elif args.db_command == "migrate":
        _db_migrate(config)
    else:
        sys.exit(1)


def _db_status(config) -> None:
    """Check database connectivity and schema status."""
    from acmeeh.db import init_database

    try:
        db = init_database(config.settings.database)
        db.fetch_value("SELECT 1")

        # Check if schema exists
        db.fetch_value(
            "SELECT count(*) FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name IN "
            "('accounts', 'orders', 'certificates', 'challenges')",
        )

        # Check admin schema
        db.fetch_value(
            "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'admin'",
        )

    except Exception:
        sys.exit(1)


def _db_migrate(config) -> None:
    """Run database schema migration."""
    from acmeeh.db import init_database

    try:
        init_database(config.settings.database)

        if config.settings.database.auto_setup:
            pass
        else:
            pass
    except Exception:
        sys.exit(1)
