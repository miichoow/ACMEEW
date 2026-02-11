"""Tests for CLI subcommand dispatch functions.

Each ``run_*`` function in ``acmeeh.cli.commands`` is a thin dispatcher
that loads the app/database and delegates to services.  We mock every
external dependency so tests run without a database or real config.

Key fix: CLI commands use deferred imports (``from acmeeh.db import
init_database`` inside function bodies), so patches must target the
*source* module, NOT the command module.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_config(**overrides):
    """Build a MagicMock that looks like an AcmeehConfig."""
    cfg = MagicMock()
    cfg.settings.admin_api.enabled = overrides.get("admin_enabled", True)
    cfg.settings.crl.enabled = overrides.get("crl_enabled", True)
    cfg.settings.database.auto_setup = overrides.get("auto_setup", True)
    cfg.settings.database.host = "localhost"
    cfg.settings.database.port = 5432
    cfg.settings.database.database = "acmeeh"
    cfg.settings.database.user = "test"
    cfg.settings.ca.backend = "internal"
    return cfg


def _mock_args(**kwargs):
    """Build a MagicMock that looks like argparse.Namespace."""
    args = MagicMock()
    for k, v in kwargs.items():
        setattr(args, k, v)
    return args


# ===========================================================================
# run_admin
# ===========================================================================


class TestRunAdmin:
    """Tests for acmeeh.cli.commands.admin.run_admin."""

    def test_unknown_command_exits(self):
        """No known admin_command triggers sys.exit(1)."""
        from acmeeh.cli.commands.admin import run_admin

        config = _mock_config()
        args = _mock_args(admin_command=None)

        with pytest.raises(SystemExit) as exc_info:
            run_admin(config, args)
        assert exc_info.value.code == 1

    def test_unknown_command_string_exits(self):
        """An unrecognised admin_command string triggers sys.exit(1)."""
        from acmeeh.cli.commands.admin import run_admin

        config = _mock_config()
        args = _mock_args(admin_command="bogus")

        with pytest.raises(SystemExit) as exc_info:
            run_admin(config, args)
        assert exc_info.value.code == 1

    def test_create_user_admin_disabled_exits(self):
        """create-user when admin_api is disabled exits 1."""
        from acmeeh.cli.commands.admin import run_admin

        config = _mock_config(admin_enabled=False)
        args = _mock_args(
            admin_command="create-user",
            username="admin",
            email="admin@example.com",
            role="admin",
        )

        with pytest.raises(SystemExit) as exc_info:
            run_admin(config, args)
        assert exc_info.value.code == 1

    def test_create_user_missing_username_exits(self):
        """create-user with no username exits 1."""
        from acmeeh.cli.commands.admin import run_admin

        config = _mock_config()
        args = _mock_args(
            admin_command="create-user",
            username="",
            email="admin@example.com",
            role="auditor",
        )

        with pytest.raises(SystemExit) as exc_info:
            run_admin(config, args)
        assert exc_info.value.code == 1

    def test_create_user_missing_email_exits(self):
        """create-user with no email exits 1."""
        from acmeeh.cli.commands.admin import run_admin

        config = _mock_config()
        args = _mock_args(
            admin_command="create-user",
            username="admin",
            email="",
            role="auditor",
        )

        with pytest.raises(SystemExit) as exc_info:
            run_admin(config, args)
        assert exc_info.value.code == 1

    def test_create_user_invalid_role_exits(self):
        """create-user with invalid role exits 1."""
        from acmeeh.cli.commands.admin import run_admin

        config = _mock_config()
        args = _mock_args(
            admin_command="create-user",
            username="admin",
            email="admin@example.com",
            role="superadmin",  # not a valid AdminRole
        )

        with pytest.raises(SystemExit) as exc_info:
            run_admin(config, args)
        assert exc_info.value.code == 1

    def test_create_user_calls_admin_service(self):
        """create-user dispatches to container.admin_service.create_user."""
        from acmeeh.cli.commands.admin import run_admin

        config = _mock_config()
        args = _mock_args(
            admin_command="create-user",
            username="admin",
            email="admin@example.com",
            role="admin",
        )

        mock_container = MagicMock()
        mock_container.admin_service.create_user.return_value = (
            MagicMock(),  # user object
            "generated-password",
        )

        mock_app = MagicMock()
        mock_app.app_context.return_value.__enter__ = MagicMock(return_value=None)
        mock_app.app_context.return_value.__exit__ = MagicMock(return_value=False)

        with (
            patch("acmeeh.db.init_database") as mock_init_db,
            patch("acmeeh.app.create_app") as mock_create_app,
            patch("acmeeh.app.context.get_container", return_value=mock_container),
        ):
            mock_init_db.return_value = MagicMock()
            mock_create_app.return_value = mock_app
            run_admin(config, args)

        mock_container.admin_service.create_user.assert_called_once()
        call_args = mock_container.admin_service.create_user.call_args
        assert call_args[0][0] == "admin"
        assert call_args[0][1] == "admin@example.com"

    def test_create_user_default_role_is_auditor(self):
        """create-user with role=None defaults to auditor."""
        from acmeeh.cli.commands.admin import run_admin

        config = _mock_config()
        args = _mock_args(
            admin_command="create-user",
            username="viewer",
            email="viewer@example.com",
            role=None,  # defaults to "auditor" in the code
        )

        mock_container = MagicMock()
        mock_container.admin_service.create_user.return_value = (MagicMock(), "pw")

        mock_app = MagicMock()
        mock_app.app_context.return_value.__enter__ = MagicMock(return_value=None)
        mock_app.app_context.return_value.__exit__ = MagicMock(return_value=False)

        with (
            patch("acmeeh.db.init_database") as mock_init_db,
            patch("acmeeh.app.create_app") as mock_create_app,
            patch("acmeeh.app.context.get_container", return_value=mock_container),
        ):
            mock_init_db.return_value = MagicMock()
            mock_create_app.return_value = mock_app
            run_admin(config, args)

        mock_container.admin_service.create_user.assert_called_once()

    def test_create_user_no_admin_service_exits(self):
        """create-user when admin_service is None on the container exits 1."""
        from acmeeh.cli.commands.admin import run_admin

        config = _mock_config()
        args = _mock_args(
            admin_command="create-user",
            username="admin",
            email="admin@example.com",
            role="admin",
        )

        mock_container = MagicMock()
        mock_container.admin_service = None

        mock_app = MagicMock()
        mock_app.app_context.return_value.__enter__ = MagicMock(return_value=None)
        mock_app.app_context.return_value.__exit__ = MagicMock(return_value=False)

        with (
            patch("acmeeh.db.init_database") as mock_init_db,
            patch("acmeeh.app.create_app") as mock_create_app,
            patch("acmeeh.app.context.get_container", return_value=mock_container),
            pytest.raises(SystemExit) as exc_info,
        ):
            mock_init_db.return_value = MagicMock()
            mock_create_app.return_value = mock_app
            run_admin(config, args)

        assert exc_info.value.code == 1


# ===========================================================================
# run_ca
# ===========================================================================


class TestRunCa:
    """Tests for acmeeh.cli.commands.ca.run_ca."""

    def test_unknown_command_exits(self):
        """No known ca_command triggers sys.exit(1)."""
        from acmeeh.cli.commands.ca import run_ca

        config = _mock_config()
        args = _mock_args(ca_command=None)

        with pytest.raises(SystemExit) as exc_info:
            run_ca(config, args)
        assert exc_info.value.code == 1

    def test_unknown_command_string_exits(self):
        """Unrecognised ca_command string exits."""
        from acmeeh.cli.commands.ca import run_ca

        config = _mock_config()
        args = _mock_args(ca_command="rotate-key")

        with pytest.raises(SystemExit) as exc_info:
            run_ca(config, args)
        assert exc_info.value.code == 1

    def test_test_sign_calls_backend_sign(self):
        """test-sign loads the CA backend and calls sign()."""
        from acmeeh.cli.commands.ca import run_ca

        config = _mock_config()
        args = _mock_args(ca_command="test-sign")

        mock_backend = MagicMock()
        mock_backend.startup_check.return_value = None
        mock_backend.sign.return_value = MagicMock()

        with patch("acmeeh.ca.registry.load_ca_backend", return_value=mock_backend):
            run_ca(config, args)

        mock_backend.startup_check.assert_called_once()
        mock_backend.sign.assert_called_once()

    def test_test_sign_backend_startup_fails_exits(self):
        """test-sign exits 1 when backend.startup_check raises."""
        from acmeeh.cli.commands.ca import run_ca

        config = _mock_config()
        args = _mock_args(ca_command="test-sign")

        mock_backend = MagicMock()
        mock_backend.startup_check.side_effect = RuntimeError("CA unavailable")

        with (
            patch("acmeeh.ca.registry.load_ca_backend", return_value=mock_backend),
            pytest.raises(SystemExit) as exc_info,
        ):
            run_ca(config, args)
        assert exc_info.value.code == 1

    def test_test_sign_sign_fails_exits(self):
        """test-sign exits 1 when backend.sign raises."""
        from acmeeh.cli.commands.ca import run_ca

        config = _mock_config()
        args = _mock_args(ca_command="test-sign")

        mock_backend = MagicMock()
        mock_backend.startup_check.return_value = None
        mock_backend.sign.side_effect = RuntimeError("sign failed")

        with (
            patch("acmeeh.ca.registry.load_ca_backend", return_value=mock_backend),
            pytest.raises(SystemExit) as exc_info,
        ):
            run_ca(config, args)
        assert exc_info.value.code == 1


# ===========================================================================
# run_crl
# ===========================================================================


class TestRunCrl:
    """Tests for acmeeh.cli.commands.crl.run_crl."""

    def test_unknown_command_exits(self):
        """No known crl_command triggers sys.exit(1)."""
        from acmeeh.cli.commands.crl import run_crl

        config = _mock_config()
        args = _mock_args(crl_command=None)

        with pytest.raises(SystemExit) as exc_info:
            run_crl(config, args)
        assert exc_info.value.code == 1

    def test_unknown_command_string_exits(self):
        """Unrecognised crl_command string exits."""
        from acmeeh.cli.commands.crl import run_crl

        config = _mock_config()
        args = _mock_args(crl_command="rotate")

        with pytest.raises(SystemExit) as exc_info:
            run_crl(config, args)
        assert exc_info.value.code == 1

    def test_rebuild_when_crl_disabled_exits(self):
        """rebuild when CRL is disabled exits 1."""
        from acmeeh.cli.commands.crl import run_crl

        config = _mock_config(crl_enabled=False)
        args = _mock_args(crl_command="rebuild")

        with pytest.raises(SystemExit) as exc_info:
            run_crl(config, args)
        assert exc_info.value.code == 1

    def test_rebuild_calls_force_rebuild(self):
        """rebuild dispatches to container.crl_manager.force_rebuild."""
        from acmeeh.cli.commands.crl import run_crl

        config = _mock_config(crl_enabled=True)
        args = _mock_args(crl_command="rebuild")

        mock_container = MagicMock()
        mock_container.crl_manager.force_rebuild.return_value = None
        mock_container.crl_manager.health_status.return_value = {}

        mock_app = MagicMock()
        mock_app.app_context.return_value.__enter__ = MagicMock(return_value=None)
        mock_app.app_context.return_value.__exit__ = MagicMock(return_value=False)

        with (
            patch("acmeeh.db.init_database") as mock_init_db,
            patch("acmeeh.app.create_app") as mock_create_app,
            patch("acmeeh.app.context.get_container", return_value=mock_container),
        ):
            mock_init_db.return_value = MagicMock()
            mock_create_app.return_value = mock_app
            run_crl(config, args)

        mock_container.crl_manager.force_rebuild.assert_called_once()
        mock_container.crl_manager.health_status.assert_called_once()

    def test_rebuild_no_crl_manager_exits(self):
        """rebuild exits 1 when container.crl_manager is None."""
        from acmeeh.cli.commands.crl import run_crl

        config = _mock_config(crl_enabled=True)
        args = _mock_args(crl_command="rebuild")

        mock_container = MagicMock()
        mock_container.crl_manager = None

        mock_app = MagicMock()
        mock_app.app_context.return_value.__enter__ = MagicMock(return_value=None)
        mock_app.app_context.return_value.__exit__ = MagicMock(return_value=False)

        with (
            patch("acmeeh.db.init_database") as mock_init_db,
            patch("acmeeh.app.create_app") as mock_create_app,
            patch("acmeeh.app.context.get_container", return_value=mock_container),
            pytest.raises(SystemExit) as exc_info,
        ):
            mock_init_db.return_value = MagicMock()
            mock_create_app.return_value = mock_app
            run_crl(config, args)

        assert exc_info.value.code == 1


# ===========================================================================
# run_db
# ===========================================================================


class TestRunDb:
    """Tests for acmeeh.cli.commands.db.run_db."""

    def test_unknown_command_exits(self):
        """No known db_command triggers sys.exit(1)."""
        from acmeeh.cli.commands.db import run_db

        config = _mock_config()
        args = _mock_args(db_command=None)

        with pytest.raises(SystemExit) as exc_info:
            run_db(config, args)
        assert exc_info.value.code == 1

    def test_unknown_command_string_exits(self):
        """Unrecognised db_command string exits."""
        from acmeeh.cli.commands.db import run_db

        config = _mock_config()
        args = _mock_args(db_command="drop-all")

        with pytest.raises(SystemExit) as exc_info:
            run_db(config, args)
        assert exc_info.value.code == 1

    def test_status_success(self):
        """status checks DB connectivity with SELECT 1."""
        from acmeeh.cli.commands.db import run_db

        config = _mock_config()
        args = _mock_args(db_command="status")

        mock_db = MagicMock()
        mock_db.fetch_value.return_value = 1

        with patch("acmeeh.db.init_database", return_value=mock_db):
            run_db(config, args)

        assert mock_db.fetch_value.call_count >= 1

    def test_status_db_fails_exits(self):
        """status exits 1 when DB connection fails."""
        from acmeeh.cli.commands.db import run_db

        config = _mock_config()
        args = _mock_args(db_command="status")

        with (
            patch("acmeeh.db.init_database", side_effect=Exception("conn refused")),
            pytest.raises(SystemExit) as exc_info,
        ):
            run_db(config, args)
        assert exc_info.value.code == 1

    def test_migrate_with_auto_setup(self):
        """migrate with auto_setup=true completes without error."""
        from acmeeh.cli.commands.db import run_db

        config = _mock_config(auto_setup=True)
        args = _mock_args(db_command="migrate")

        mock_db = MagicMock()

        with patch("acmeeh.db.init_database", return_value=mock_db):
            run_db(config, args)

    def test_migrate_without_auto_setup(self):
        """migrate with auto_setup=false still completes."""
        from acmeeh.cli.commands.db import run_db

        config = _mock_config(auto_setup=False)
        args = _mock_args(db_command="migrate")

        mock_db = MagicMock()

        with patch("acmeeh.db.init_database", return_value=mock_db):
            run_db(config, args)

    def test_migrate_db_init_fails_exits(self):
        """migrate exits 1 when init_database raises."""
        from acmeeh.cli.commands.db import run_db

        config = _mock_config()
        args = _mock_args(db_command="migrate")

        with (
            patch("acmeeh.db.init_database", side_effect=Exception("boom")),
            pytest.raises(SystemExit) as exc_info,
        ):
            run_db(config, args)
        assert exc_info.value.code == 1


# ===========================================================================
# run_inspect
# ===========================================================================


class TestRunInspect:
    """Tests for acmeeh.cli.commands.inspect.run_inspect."""

    def test_no_inspect_command_exits(self):
        """Missing inspect_command attribute exits 1."""
        from acmeeh.cli.commands.inspect import run_inspect

        config = _mock_config()
        args = MagicMock(spec=[])  # no inspect_command attribute at all

        with pytest.raises(SystemExit) as exc_info:
            run_inspect(config, args)
        assert exc_info.value.code == 1

    def test_none_inspect_command_exits(self):
        """inspect_command=None exits 1."""
        from acmeeh.cli.commands.inspect import run_inspect

        config = _mock_config()
        args = _mock_args(inspect_command=None)

        with pytest.raises(SystemExit) as exc_info:
            run_inspect(config, args)
        assert exc_info.value.code == 1

    def test_unknown_sub_exits(self):
        """Unrecognised inspect sub-command exits 1."""
        from acmeeh.cli.commands.inspect import run_inspect

        config = _mock_config()
        args = _mock_args(inspect_command="nonce", resource_id="abc")

        mock_db = MagicMock()

        with (
            patch("acmeeh.db.init_database", return_value=mock_db),
            pytest.raises(SystemExit) as exc_info,
        ):
            run_inspect(config, args)
        assert exc_info.value.code == 1

    def test_inspect_order_valid_uuid(self):
        """inspect order with a valid UUID queries repos."""
        from acmeeh.cli.commands.inspect import run_inspect

        config = _mock_config()
        order_id = str(uuid4())
        args = _mock_args(inspect_command="order", resource_id=order_id)

        mock_db = MagicMock()
        mock_order = MagicMock()
        mock_order.id = order_id
        mock_order.account_id = uuid4()
        mock_order.status.value = "pending"
        mock_order.identifiers = []
        mock_order.expires = None
        mock_order.created_at = None
        mock_order.certificate_id = None
        mock_order.error = None

        mock_order_repo = MagicMock()
        mock_order_repo.find_by_id.return_value = mock_order
        mock_order_repo.find_authorization_ids.return_value = []

        mock_authz_repo = MagicMock()
        mock_challenge_repo = MagicMock()

        with (
            patch("acmeeh.db.init_database", return_value=mock_db),
            patch("acmeeh.repositories.order.OrderRepository", return_value=mock_order_repo),
            patch(
                "acmeeh.repositories.authorization.AuthorizationRepository",
                return_value=mock_authz_repo,
            ),
            patch(
                "acmeeh.repositories.challenge.ChallengeRepository",
                return_value=mock_challenge_repo,
            ),
        ):
            run_inspect(config, args)

        mock_order_repo.find_by_id.assert_called_once()

    def test_inspect_order_invalid_uuid_exits(self):
        """inspect order with invalid UUID exits 1."""
        from acmeeh.cli.commands.inspect import run_inspect

        config = _mock_config()
        args = _mock_args(inspect_command="order", resource_id="not-a-uuid")

        mock_db = MagicMock()

        with (
            patch("acmeeh.db.init_database", return_value=mock_db),
            patch("acmeeh.repositories.order.OrderRepository"),
            patch("acmeeh.repositories.authorization.AuthorizationRepository"),
            patch("acmeeh.repositories.challenge.ChallengeRepository"),
            pytest.raises(SystemExit) as exc_info,
        ):
            run_inspect(config, args)
        assert exc_info.value.code == 1

    def test_inspect_order_not_found_exits(self):
        """inspect order that doesn't exist exits 1."""
        from acmeeh.cli.commands.inspect import run_inspect

        config = _mock_config()
        order_id = str(uuid4())
        args = _mock_args(inspect_command="order", resource_id=order_id)

        mock_db = MagicMock()
        mock_order_repo = MagicMock()
        mock_order_repo.find_by_id.return_value = None

        with (
            patch("acmeeh.db.init_database", return_value=mock_db),
            patch("acmeeh.repositories.order.OrderRepository", return_value=mock_order_repo),
            patch("acmeeh.repositories.authorization.AuthorizationRepository"),
            patch("acmeeh.repositories.challenge.ChallengeRepository"),
            pytest.raises(SystemExit) as exc_info,
        ):
            run_inspect(config, args)
        assert exc_info.value.code == 1

    def test_inspect_certificate_by_uuid(self):
        """inspect certificate by valid UUID queries the repo."""
        from acmeeh.cli.commands.inspect import run_inspect

        config = _mock_config()
        cert_id = str(uuid4())
        args = _mock_args(inspect_command="certificate", resource_id=cert_id)

        mock_db = MagicMock()
        mock_cert = MagicMock()
        mock_cert.id = cert_id
        mock_cert.account_id = uuid4()
        mock_cert.order_id = None
        mock_cert.serial_number = "ABC123"
        mock_cert.fingerprint = "sha256:deadbeef"
        mock_cert.not_before_cert = None
        mock_cert.not_after_cert = None
        mock_cert.revoked_at = None
        mock_cert.revocation_reason = None
        mock_cert.san_values = ["example.com"]
        mock_cert.public_key_fingerprint = "sha256:cafe"
        mock_cert.created_at = None

        mock_cert_repo = MagicMock()
        mock_cert_repo.find_by_id.return_value = mock_cert

        with (
            patch("acmeeh.db.init_database", return_value=mock_db),
            patch(
                "acmeeh.repositories.certificate.CertificateRepository", return_value=mock_cert_repo
            ),
        ):
            run_inspect(config, args)

        mock_cert_repo.find_by_id.assert_called_once()

    def test_inspect_certificate_by_serial(self):
        """inspect certificate by serial number queries find_by_serial."""
        from acmeeh.cli.commands.inspect import run_inspect

        config = _mock_config()
        serial = "01:AB:CD:EF"
        args = _mock_args(inspect_command="certificate", resource_id=serial)

        mock_db = MagicMock()
        mock_cert = MagicMock()
        mock_cert.id = uuid4()
        mock_cert.account_id = uuid4()
        mock_cert.order_id = None
        mock_cert.serial_number = serial
        mock_cert.fingerprint = "sha256:deadbeef"
        mock_cert.not_before_cert = None
        mock_cert.not_after_cert = None
        mock_cert.revoked_at = None
        mock_cert.revocation_reason = None
        mock_cert.san_values = []
        mock_cert.public_key_fingerprint = "sha256:cafe"
        mock_cert.created_at = None

        mock_cert_repo = MagicMock()
        mock_cert_repo.find_by_id.return_value = None
        mock_cert_repo.find_by_serial.return_value = mock_cert

        with (
            patch("acmeeh.db.init_database", return_value=mock_db),
            patch(
                "acmeeh.repositories.certificate.CertificateRepository", return_value=mock_cert_repo
            ),
        ):
            run_inspect(config, args)

        mock_cert_repo.find_by_serial.assert_called_once_with(serial)

    def test_inspect_certificate_not_found_exits(self):
        """inspect certificate that doesn't exist exits 1."""
        from acmeeh.cli.commands.inspect import run_inspect

        config = _mock_config()
        args = _mock_args(inspect_command="certificate", resource_id="nonexistent")

        mock_db = MagicMock()
        mock_cert_repo = MagicMock()
        mock_cert_repo.find_by_id.return_value = None
        mock_cert_repo.find_by_serial.return_value = None

        with (
            patch("acmeeh.db.init_database", return_value=mock_db),
            patch(
                "acmeeh.repositories.certificate.CertificateRepository", return_value=mock_cert_repo
            ),
            pytest.raises(SystemExit) as exc_info,
        ):
            run_inspect(config, args)
        assert exc_info.value.code == 1

    def test_inspect_account_valid_uuid(self):
        """inspect account with a valid UUID queries repos."""
        from acmeeh.cli.commands.inspect import run_inspect

        config = _mock_config()
        account_id = str(uuid4())
        args = _mock_args(inspect_command="account", resource_id=account_id)

        mock_db = MagicMock()
        mock_account = MagicMock()
        mock_account.id = account_id
        mock_account.status.value = "valid"
        mock_account.tos_agreed = True
        mock_account.created_at = None

        mock_account_repo = MagicMock()
        mock_account_repo.find_by_id.return_value = mock_account

        mock_contact_repo = MagicMock()
        mock_contact_repo.find_by_account.return_value = []

        mock_order_repo = MagicMock()
        mock_order_repo.find_by_account.return_value = []

        with (
            patch("acmeeh.db.init_database", return_value=mock_db),
            patch("acmeeh.repositories.account.AccountRepository", return_value=mock_account_repo),
            patch("acmeeh.repositories.AccountContactRepository", return_value=mock_contact_repo),
            patch("acmeeh.repositories.OrderRepository", return_value=mock_order_repo),
        ):
            run_inspect(config, args)

        mock_account_repo.find_by_id.assert_called_once()

    def test_inspect_account_invalid_uuid_exits(self):
        """inspect account with invalid UUID exits 1."""
        from acmeeh.cli.commands.inspect import run_inspect

        config = _mock_config()
        args = _mock_args(inspect_command="account", resource_id="not-a-uuid")

        mock_db = MagicMock()

        with (
            patch("acmeeh.db.init_database", return_value=mock_db),
            patch("acmeeh.repositories.account.AccountRepository"),
            patch("acmeeh.repositories.AccountContactRepository"),
            patch("acmeeh.repositories.OrderRepository"),
            pytest.raises(SystemExit) as exc_info,
        ):
            run_inspect(config, args)
        assert exc_info.value.code == 1

    def test_inspect_account_not_found_exits(self):
        """inspect account that doesn't exist exits 1."""
        from acmeeh.cli.commands.inspect import run_inspect

        config = _mock_config()
        account_id = str(uuid4())
        args = _mock_args(inspect_command="account", resource_id=account_id)

        mock_db = MagicMock()
        mock_account_repo = MagicMock()
        mock_account_repo.find_by_id.return_value = None

        with (
            patch("acmeeh.db.init_database", return_value=mock_db),
            patch("acmeeh.repositories.account.AccountRepository", return_value=mock_account_repo),
            patch("acmeeh.repositories.AccountContactRepository"),
            patch("acmeeh.repositories.OrderRepository"),
            pytest.raises(SystemExit) as exc_info,
        ):
            run_inspect(config, args)
        assert exc_info.value.code == 1


# ===========================================================================
# run_serve
# ===========================================================================


class TestRunServe:
    """Tests for acmeeh.cli.commands.serve.run_serve."""

    def test_dev_mode_calls_app_run(self):
        """In dev mode, the Flask app.run() method is called."""
        from acmeeh.cli.commands.serve import run_serve

        config = _mock_config()
        config.settings.server.bind = "127.0.0.1"
        config.settings.server.port = 8443
        args = _mock_args(dev=True)

        mock_app = MagicMock()

        with (
            patch("acmeeh.db.init_database") as mock_init_db,
            patch("acmeeh.app.create_app", return_value=mock_app),
            patch("pathlib.Path.is_file", return_value=False),
        ):
            mock_init_db.return_value = MagicMock()
            run_serve(config, args)

        mock_app.run.assert_called_once()
        call_kwargs = mock_app.run.call_args[1]
        assert call_kwargs["host"] == "127.0.0.1"
        assert call_kwargs["port"] == 8443
        assert call_kwargs["debug"] is True

    def test_production_mode_calls_gunicorn(self):
        """In production mode (dev=False), run_gunicorn is called."""
        from acmeeh.cli.commands.serve import run_serve

        config = _mock_config()
        args = _mock_args(dev=False)

        mock_app = MagicMock()

        with (
            patch("acmeeh.db.init_database") as mock_init_db,
            patch("acmeeh.app.create_app", return_value=mock_app),
            patch("acmeeh.server.gunicorn_app.run_gunicorn") as mock_gunicorn,
        ):
            mock_init_db.return_value = MagicMock()
            run_serve(config, args)

        mock_gunicorn.assert_called_once_with(mock_app, config.settings.server)

    def test_dev_mode_with_tls_files(self):
        """In dev mode with TLS files present, ssl_context is set."""
        from acmeeh.cli.commands.serve import run_serve

        config = _mock_config()
        config.settings.server.bind = "0.0.0.0"
        config.settings.server.port = 8443
        args = _mock_args(dev=True)

        mock_app = MagicMock()

        with (
            patch("acmeeh.db.init_database") as mock_init_db,
            patch("acmeeh.app.create_app", return_value=mock_app),
            patch("pathlib.Path.is_file", return_value=True),
        ):
            mock_init_db.return_value = MagicMock()
            run_serve(config, args)

        call_kwargs = mock_app.run.call_args[1]
        assert call_kwargs["ssl_context"] is not None
