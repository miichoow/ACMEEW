"""Flask application package for ACMEEH.

Public API::

    from acmeeh.app import create_app
"""

from acmeeh.app.factory import create_app

__all__ = ["create_app"]
