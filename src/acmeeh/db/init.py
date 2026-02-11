"""Database initialisation from ACMEEH configuration.

Usage::

    from acmeeh.config import get_config
    from acmeeh.db.init import init_database

    init_database(get_config().settings.database)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from pypgkit import Database, DatabaseConfig

if TYPE_CHECKING:
    from acmeeh.config.settings import DatabaseSettings

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"

log = logging.getLogger(__name__)


def _settings_to_config(settings: DatabaseSettings) -> DatabaseConfig:
    """Map ACMEEH DatabaseSettings to PyPGKit DatabaseConfig."""
    return DatabaseConfig(
        host=settings.host,
        port=settings.port,
        database=settings.database,
        user=settings.user,
        password=settings.password,
        sslmode=settings.sslmode,
        min_connections=settings.min_connections,
        max_connections=settings.max_connections,
        connection_timeout=settings.connection_timeout,
    )


def init_database(settings: DatabaseSettings) -> Database:
    """Initialise the :class:`Database` singleton from config settings.

    If the singleton is already initialised, returns the existing instance.

    Parameters
    ----------
    settings:
        The ``database`` section from :class:`AcmeehSettings`.

    Returns
    -------
    Database
        The ready-to-use database instance.

    """
    if Database.is_initialized():
        log.debug("Database already initialised, returning existing instance")
        return Database.get_instance()

    config = _settings_to_config(settings)

    log.info(
        "Initialising database connection: %s@%s:%s/%s",
        settings.user,
        settings.host,
        settings.port,
        settings.database,
    )

    db = Database.init(
        config=config,
        schema_path=_SCHEMA_PATH if settings.auto_setup else None,
        auto_setup=settings.auto_setup,
        interactive=False,
    )

    log.info("Database initialised successfully")
    return db
