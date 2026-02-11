"""CRL management subcommands."""

from __future__ import annotations

import logging
import sys

log = logging.getLogger(__name__)


def run_crl(config, args) -> None:
    """Handle crl subcommands."""
    if args.crl_command == "rebuild":
        _crl_rebuild(config)
    else:
        sys.exit(1)


def _crl_rebuild(config) -> None:
    """Force a CRL rebuild."""
    if not config.settings.crl.enabled:
        sys.exit(1)

    from acmeeh.app import create_app
    from acmeeh.db import init_database

    db = init_database(config.settings.database)
    app = create_app(config=config, database=db)

    with app.app_context():
        from acmeeh.app.context import get_container

        container = get_container()
        if container.crl_manager is None:
            sys.exit(1)

        container.crl_manager.force_rebuild()
        container.crl_manager.health_status()
