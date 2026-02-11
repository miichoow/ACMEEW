"""WSGI entry point for external servers (gunicorn, uWSGI, etc.).

The config file path is read from the ``ACMEEH_CONFIG`` environment
variable.

Example::

    export ACMEEH_CONFIG=/etc/acmeeh/config.yaml
    gunicorn "acmeeh.server.wsgi:app"
"""

from __future__ import annotations

import os
import sys

_config_path = os.environ.get("ACMEEH_CONFIG")
if _config_path is None:
    sys.exit(1)

# Bootstrap the singleton before anything else imports it.
from acmeeh.config import AcmeehConfig  # noqa: E402

_config = AcmeehConfig(config_file=_config_path, schema_file="bundled")

from acmeeh.logging import configure_logging  # noqa: E402

configure_logging(_config.settings.logging)

from acmeeh.db import init_database  # noqa: E402

_db = init_database(_config.settings.database)

from acmeeh.app import create_app  # noqa: E402

app = create_app(config=_config, database=_db)
