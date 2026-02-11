===========
Development
===========

*Project structure, testing, hooks, and contributing*

Project Structure
-----------------

.. code-block:: text

   src/acmeeh/
   ├── __init__.py              # Version: 1.0.0
   ├── __main__.py              # CLI entry point
   ├── cli/
   │   ├── main.py              # Argument parsing & dispatch
   │   └── commands/
   │       ├── admin.py         # admin create-user
   │       ├── ca.py            # ca test-sign
   │       ├── crl.py           # crl rebuild
   │       ├── db.py            # db status, db migrate
   │       └── inspect.py       # inspect order/certificate/account
   ├── config/
   │   ├── __init__.py          # Exports AcmeehConfig, get_config
   │   ├── acmeeh_config.py     # ConfigKit subclass
   │   ├── settings.py          # Frozen dataclasses (27 sections)
   │   └── schema.json          # JSON Schema validation
   ├── app/
   │   ├── factory.py           # create_app(config, database)
   │   ├── context.py           # DI container: get_container()
   │   └── errors.py            # AcmeProblem exception
   ├── core/
   │   ├── types.py             # Enums: OrderStatus, ChallengeType, etc.
   │   ├── state.py             # State machine transitions
   │   └── jws.py               # JWS/JWK/JWK Thumbprint (RFC 7515/7517/7638)
   ├── api/
   │   ├── __init__.py          # register_blueprints()
   │   ├── directory.py         # GET /directory
   │   ├── nonce.py             # HEAD/GET /new-nonce
   │   ├── account.py           # POST /new-account, /acct/{id}
   │   ├── order.py             # POST /new-order, /order/{id}, /order/{id}/finalize
   │   ├── authorization.py     # POST /authz/{id}
   │   ├── challenge_routes.py  # POST /chall/{id}
   │   ├── certificate.py       # POST /cert/{id}, /revoke-cert
   │   ├── key_change.py        # POST /key-change
   │   ├── new_authz.py         # POST /new-authz
   │   ├── crl.py               # GET /crl (optional)
   │   ├── ocsp.py              # POST/GET /ocsp (optional)
   │   ├── renewal_info.py      # GET /renewalInfo/{id} (optional)
   │   ├── metrics.py           # GET /metrics (optional)
   │   └── decorators.py        # ACME response headers
   ├── models/                  # Frozen dataclass models
   │   ├── account.py
   │   ├── authorization.py
   │   ├── certificate.py
   │   ├── challenge.py
   │   ├── identifier.py
   │   ├── nonce.py
   │   ├── notification.py
   │   └── order.py
   ├── repositories/            # BaseRepository[T] subclasses
   │   ├── account.py
   │   ├── account_contact.py
   │   ├── authorization.py
   │   ├── certificate.py
   │   ├── challenge.py
   │   ├── nonce.py
   │   ├── notification.py
   │   └── order.py
   ├── services/                # Business logic
   │   ├── account.py
   │   ├── authorization.py
   │   ├── certificate.py
   │   ├── challenge.py
   │   ├── key_change.py
   │   ├── nonce.py
   │   ├── notification.py
   │   └── order.py
   ├── ca/                      # CA backends
   │   ├── base.py              # CABackend ABC, IssuedCertificate
   │   ├── registry.py          # Backend loader/registry
   │   ├── internal.py          # File-based CA
   │   ├── external.py          # HTTP API CA
   │   ├── hsm.py               # PKCS#11 HSM CA
   │   └── acme_proxy.py        # Upstream ACME CA
   ├── challenge/               # Challenge validators
   ├── hooks/                   # Hook system
   │   ├── base.py              # Hook ABC
   │   └── events.py            # Event definitions
   ├── admin/                   # Admin API
   │   ├── routes.py            # Flask blueprint
   │   ├── auth.py              # JWT auth, rate limiting
   │   ├── service.py           # AdminUserService
   │   ├── serializers.py       # JSON serializers
   │   └── pagination.py        # Cursor-based pagination
   ├── notifications/           # Email notification system
   ├── metrics/                 # Prometheus metrics
   ├── logging/                 # Structured logging setup
   ├── server/                  # Gunicorn app wrapper
   └── db/
       └── schema.sql           # Database schema

Running Tests
-------------

.. code-block:: bash

   # Run all tests
   PYTHONPATH=src python -m pytest tests/

   # Run a specific test file
   PYTHONPATH=src python -m pytest tests/test_config.py -v

   # Run a single test
   PYTHONPATH=src python -m pytest tests/test_config.py::test_name -v

   # Run with coverage
   PYTHONPATH=src python -m pytest tests/ --cov=acmeeh --cov-report=html

.. note::

   **Config Reset**

   The ``fresh_config`` autouse fixture in ``tests/conftest.py`` automatically resets the ConfigKit singleton before and after every test. You don't need to worry about config leaking between tests.

Test Structure
--------------

.. code-block:: text

   tests/
   ├── conftest.py              # Shared fixtures (fresh_config, etc.)
   ├── test_config.py
   ├── test_settings.py
   ├── test_jws.py
   ├── test_state.py
   ├── ...
   └── integration/
       ├── conftest.py          # Full app fixtures with mocked DB
       ├── test_directory.py
       ├── test_account.py
       ├── test_order.py
       └── ...

.. _hooks:

Hook System
-----------

ACMEEH has a pluggable hook system that fires on lifecycle events. Hooks run asynchronously in a thread pool and don't block the request.

Available Events
^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 25 25 30

   * - Event
     - Method
     - Fires When
     - Context Keys
   * - ``account.registration``
     - ``on_account_registration``
     - New account is created
     - ``account_id``, ``contacts``, ``jwk_thumbprint``, ``tos_agreed``
   * - ``order.creation``
     - ``on_order_creation``
     - New order is submitted
     - ``order_id``, ``account_id``, ``identifiers``, ``authz_ids``
   * - ``challenge.before_validate``
     - ``on_challenge_before_validate``
     - Before challenge validation starts
     - ``challenge_type``, ``token``, ``identifier_type``, ``identifier_value``
   * - ``challenge.after_validate``
     - ``on_challenge_after_validate``
     - After successful validation
     - ``challenge_type``, ``token``, ``identifier_type``, ``identifier_value``, ``result``
   * - ``challenge.on_failure``
     - ``on_challenge_failure``
     - Challenge validation fails terminally
     - ``challenge_type``, ``token``, ``identifier_type``, ``identifier_value``, ``error``
   * - ``challenge.on_retry``
     - ``on_challenge_retry``
     - Challenge validation fails, will retry
     - ``challenge_type``, ``token``, ``identifier_type``, ``identifier_value``, ``error``, ``retry_count``
   * - ``certificate.issuance``
     - ``on_certificate_issuance``
     - Certificate is issued
     - ``certificate_id``, ``order_id``, ``account_id``, ``serial_number``, ``domains``, ``not_after``
   * - ``certificate.revocation``
     - ``on_certificate_revocation``
     - Certificate is revoked
     - ``certificate_id``, ``account_id``, ``serial_number``, ``reason``
   * - ``certificate.delivery``
     - ``on_certificate_delivery``
     - Certificate is downloaded
     - ``certificate_id``, ``account_id``, ``serial_number``
   * - ``ct.submission``
     - ``on_ct_submission``
     - Certificate submitted to CT log
     - ``certificate_id``, ``serial_number``, ``ct_log_url``, ``sct``

Writing a Hook
^^^^^^^^^^^^^^

All custom hooks must inherit from ``Hook`` and override the event methods they need. Unimplemented methods are no-ops. The constructor receives an optional ``config`` dict from the hook entry in the YAML configuration.

.. code-block:: python

   from acmeeh.hooks.base import Hook

   class SlackNotifier(Hook):
       def __init__(self, config: dict | None = None):
           super().__init__(config)
           self.webhook_url = self.config["webhook_url"]

       @classmethod
       def validate_config(cls, config: dict) -> None:
           # Called at load time — raise ValueError if invalid
           if "webhook_url" not in config:
               raise ValueError("webhook_url is required")

       def on_certificate_issuance(self, ctx: dict):
           # ctx contains: certificate_id, order_id, account_id,
           #   serial_number, domains, not_after
           domains = ctx["domains"]
           serial = ctx["serial_number"]
           # POST to Slack webhook...

       def on_certificate_revocation(self, ctx: dict):
           # ctx contains: certificate_id, account_id,
           #   serial_number, reason
           ...

Register the hook in config:

.. code-block:: yaml

   hooks:
     timeout_seconds: 30
     max_workers: 4
     registered:
       - class: my_hooks.SlackNotifier
         enabled: true
         events:
           - certificate.issuance
           - certificate.revocation
         config:
           webhook_url: https://hooks.slack.com/...

Built-in Hooks
^^^^^^^^^^^^^^

ACMEEH ships with two built-in hook implementations:

.. list-table::
   :header-rows: 1
   :widths: 20 30 50

   * - Hook
     - Module
     - Purpose
   * - CT Log Hook
     - ``acmeeh.hooks.ct_hook``
     - Submits issued certificates to Certificate Transparency logs (configured via ``ct_logging`` settings)
   * - Audit Export Hook
     - ``acmeeh.hooks.audit_export_hook``
     - Exports audit events to external systems via webhook or syslog (configured via ``audit_export`` settings)

.. _enums:

Enum Reference
--------------

Core enumerated types from ``core/types.py`` used throughout the API and database.

AccountStatus
^^^^^^^^^^^^^

- ``valid`` --- Active account
- ``deactivated`` --- Self-deactivated by account holder
- ``revoked`` --- Revoked by administrator

OrderStatus
^^^^^^^^^^^

- ``pending`` --- Awaiting challenge validation
- ``ready`` --- All authorizations valid, ready for finalization
- ``processing`` --- CSR submitted, certificate being issued
- ``valid`` --- Certificate issued
- ``invalid`` --- One or more authorizations failed

AuthorizationStatus
^^^^^^^^^^^^^^^^^^^

- ``pending`` --- Awaiting challenge completion
- ``valid`` --- Successfully validated
- ``invalid`` --- Validation failed
- ``deactivated`` --- Deactivated by account holder
- ``expired`` --- Passed expiration time
- ``revoked`` --- Revoked by administrator

ChallengeStatus
^^^^^^^^^^^^^^^

- ``pending`` --- Waiting for client to respond
- ``processing`` --- Validation in progress
- ``valid`` --- Validation succeeded
- ``invalid`` --- Validation failed

RevocationReason (RFC 5280 \u00a75.3.1)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 10 25 65

   * - Code
     - Name
     - Description
   * - 0
     - ``unspecified``
     - No specific reason
   * - 1
     - ``keyCompromise``
     - Private key compromised
   * - 2
     - ``cACompromise``
     - CA key compromised
   * - 3
     - ``affiliationChanged``
     - Subject's affiliation changed
   * - 4
     - ``superseded``
     - Certificate replaced by a new one
   * - 5
     - ``cessationOfOperation``
     - Subject no longer operates
   * - 6
     - ``certificateHold``
     - Certificate temporarily suspended
   * - 8
     - ``removeFromCRL``
     - Remove from CRL (delta CRL)
   * - 9
     - ``privilegeWithdrawn``
     - Privilege for certificate withdrawn
   * - 10
     - ``aACompromise``
     - Attribute Authority compromised

NotificationType
^^^^^^^^^^^^^^^^

- ``delivery_succeeded``, ``delivery_failed`` --- Certificate delivery events
- ``revocation_succeeded``, ``revocation_failed`` --- Revocation events
- ``registration_succeeded``, ``registration_failed`` --- Account registration events
- ``admin_user_created``, ``admin_password_reset`` --- Admin user events
- ``expiration_warning`` --- Certificate expiration warning

AdminRole
^^^^^^^^^

- ``admin`` --- Full access to all admin API endpoints
- ``auditor`` --- Read-only access to users, audit logs, certificates, and CSR profiles

Adding a CA Backend
-------------------

To add a new built-in CA backend, update all of the following:

#. **``config/settings.py``** --- Add a new frozen dataclass for the backend's settings and a ``_build_*`` function. Add the field to ``CASettings``.
#. **``config/schema.json``** --- Add the JSON Schema definition for the new backend's configuration.
#. **``config/acmeeh_config.py``** --- Add any validation rules in ``additional_checks()``.
#. **``ca/registry.py``** --- Register the new backend name in the registry so it can be loaded.
#. **``ca/your_backend.py``** --- Implement the ``CABackend`` subclass.
#. **Tests** --- Update all test files that construct ``CASettings`` directly to include the new field.

.. warning::

   **Important**

   Many tests construct ``CASettings`` directly. If you add a field, you must update every test that does so, or tests will fail with missing argument errors.

Adding a Challenge Validator
----------------------------

Challenge validators live in ``challenge/`` and implement the validation logic for each challenge type. To add a new type:

#. Add the challenge type to ``core/types.py`` in the ``ChallengeType`` enum
#. Create a validator class in ``challenge/``
#. Register it in the challenge registry
#. Add configuration in ``config/settings.py``
#. Update ``config/schema.json``

CLI Commands Reference
----------------------

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Command
     - Description
   * - ``acmeeh -c config.yaml``
     - Start the server (default command)
   * - ``acmeeh -c config.yaml serve``
     - Explicit serve command
   * - ``acmeeh -c config.yaml serve --dev``
     - Start Flask development server
   * - ``acmeeh -c config.yaml --validate-only``
     - Validate config and exit
   * - ``acmeeh -c config.yaml db status``
     - Check database connectivity
   * - ``acmeeh -c config.yaml db migrate``
     - Run database migrations
   * - ``acmeeh -c config.yaml ca test-sign``
     - Test CA signing with ephemeral CSR
   * - ``acmeeh -c config.yaml crl rebuild``
     - Force CRL rebuild
   * - ``acmeeh -c config.yaml admin create-user``
     - Create admin user (--username, --email, --role)
   * - ``acmeeh -c config.yaml inspect order {id}``
     - Inspect an order by UUID
   * - ``acmeeh -c config.yaml inspect certificate {id}``
     - Inspect a certificate by UUID or serial
   * - ``acmeeh -c config.yaml inspect account {id}``
     - Inspect an account by UUID

Global Flags
^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Flag
     - Description
   * - ``-c, --config PATH``
     - Path to configuration file (required)
   * - ``--debug``
     - Enable debug output (full tracebacks)
   * - ``--dev``
     - Use Flask dev server instead of gunicorn
   * - ``--validate-only``
     - Validate config and exit
   * - ``-v, --version``
     - Show version and exit

Code Conventions
----------------

- **Models** --- All model classes are frozen dataclasses (immutable after creation)
- **Repositories** --- Extend ``BaseRepository[T]`` from PyPGKit. Return model instances.
- **Services** --- Business logic layer. Coordinate between repositories and CA backends.
- **Errors** --- Use ``AcmeProblem`` for all user-facing errors. Follows RFC 7807 Problem Details.
- **JWS** --- Custom implementation in ``core/jws.py`` using the ``cryptography`` library (no josepy dependency).
- **Config** --- ConfigKit singleton via metaclass. Always reset between tests.
- **Contact validation** --- Email regex requires a dot in the domain part (``test@localhost`` is rejected).
- **SQL schema** --- Tables use ``IF NOT EXISTS``; triggers use ``DROP IF EXISTS`` + ``CREATE``.
