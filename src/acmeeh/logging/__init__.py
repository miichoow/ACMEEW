"""Logging subsystem for ACMEEH.

Public API::

    from acmeeh.logging import configure_logging

    configure_logging(settings.logging)
"""

from acmeeh.logging.setup import configure_logging

__all__ = ["configure_logging"]
