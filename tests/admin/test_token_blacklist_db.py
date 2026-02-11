"""Tests for database-backed paths in TokenBlacklist (admin/auth.py lines 54-134).

Covers: set_db, revoke_token (DB success/failure/no-DB), is_revoked (DB found/
not-found/exception/no-DB/not-revoked), cleanup (DB success/exception/expired
memory/no expired memory), and _extract_signature.
"""

import logging
import time
from unittest.mock import MagicMock

from acmeeh.admin.auth import TokenBlacklist


class TestSetDb:
    """set_db(db) changes _db attribute."""

    def test_set_db_attaches_database(self):
        bl = TokenBlacklist()
        assert bl._db is None
        db = MagicMock()
        bl.set_db(db)
        assert bl._db is db

    def test_set_db_replaces_existing(self):
        db1 = MagicMock()
        db2 = MagicMock()
        bl = TokenBlacklist(db=db1)
        bl.set_db(db2)
        assert bl._db is db2


class TestRevokeTokenDbSuccess:
    """DB insert succeeds -> token NOT stored in memory (return early)."""

    def test_revoke_db_success_not_stored_in_memory(self):
        db = MagicMock()
        bl = TokenBlacklist(db=db)
        bl.revoke_token("header.payload.sig123")
        db.execute.assert_called_once()
        assert "sig123" not in bl._revoked

    def test_revoke_db_success_calls_insert_with_signature(self):
        db = MagicMock()
        bl = TokenBlacklist(db=db)
        bl.revoke_token("header.payload.mysignature")
        args, kwargs = db.execute.call_args
        sql = args[0]
        params = args[1]
        assert "INSERT INTO admin.token_blacklist" in sql
        assert params[0] == "mysignature"

    def test_revoke_db_success_with_custom_max_age(self):
        db = MagicMock()
        bl = TokenBlacklist(db=db)
        bl.revoke_token("header.payload.sig", max_age_seconds=7200)
        db.execute.assert_called_once()
        args, _ = db.execute.call_args
        params = args[1]
        # The signature should be extracted correctly
        assert params[0] == "sig"
        # expires_at should be set (second param)
        assert params[1] is not None


class TestRevokeTokenDbFailure:
    """DB insert raises -> fallback to memory storage, logged."""

    def test_revoke_db_exception_falls_back_to_memory(self, caplog):
        db = MagicMock()
        db.execute.side_effect = RuntimeError("DB down")
        bl = TokenBlacklist(db=db)
        with caplog.at_level(logging.ERROR):
            bl.revoke_token("header.payload.sig456")
        assert "sig456" in bl._revoked
        assert "Failed to write token to DB blacklist" in caplog.text

    def test_revoke_db_exception_logs_as_exception(self, caplog):
        db = MagicMock()
        db.execute.side_effect = ConnectionError("connection lost")
        bl = TokenBlacklist(db=db)
        with caplog.at_level(logging.ERROR):
            bl.revoke_token("a.b.fallbacksig")
        assert "falling back to memory" in caplog.text
        assert "fallbacksig" in bl._revoked


class TestRevokeTokenNoDb:
    """No DB -> stored in memory."""

    def test_revoke_no_db_stores_in_memory(self):
        bl = TokenBlacklist()
        bl.revoke_token("header.payload.sig789")
        assert "sig789" in bl._revoked

    def test_revoke_no_db_stores_monotonic_timestamp(self):
        bl = TokenBlacklist()
        before = time.monotonic()
        bl.revoke_token("header.payload.timesig")
        after = time.monotonic()
        assert before <= bl._revoked["timesig"] <= after


class TestIsRevokedDbFound:
    """DB query returns 1 -> True."""

    def test_is_revoked_db_found(self):
        db = MagicMock()
        db.fetch_value.return_value = 1
        bl = TokenBlacklist(db=db)
        assert bl.is_revoked("header.payload.sig") is True

    def test_is_revoked_db_found_queries_correct_signature(self):
        db = MagicMock()
        db.fetch_value.return_value = 1
        bl = TokenBlacklist(db=db)
        bl.is_revoked("x.y.target_sig")
        args, _ = db.fetch_value.call_args
        sql = args[0]
        params = args[1]
        assert "SELECT 1 FROM admin.token_blacklist" in sql
        assert params[0] == "target_sig"


class TestIsRevokedDbNotFound:
    """DB query returns None -> check memory (False if not in memory)."""

    def test_is_revoked_db_not_found_checks_memory(self):
        db = MagicMock()
        db.fetch_value.return_value = None
        bl = TokenBlacklist(db=db)
        assert bl.is_revoked("header.payload.sig") is False

    def test_is_revoked_db_not_found_but_in_memory(self):
        db = MagicMock()
        db.fetch_value.return_value = None
        bl = TokenBlacklist(db=db)
        bl._revoked["memsig"] = time.monotonic()
        assert bl.is_revoked("header.payload.memsig") is True


class TestIsRevokedDbException:
    """DB query raises -> fallback to memory check, logged."""

    def test_is_revoked_db_exception_falls_back_to_memory(self, caplog):
        db = MagicMock()
        db.fetch_value.side_effect = RuntimeError("DB error")
        bl = TokenBlacklist(db=db)
        bl._revoked["sig"] = time.monotonic()
        with caplog.at_level(logging.ERROR):
            result = bl.is_revoked("header.payload.sig")
        assert result is True
        assert "Failed to check DB token blacklist" in caplog.text

    def test_is_revoked_db_exception_not_in_memory_returns_false(self, caplog):
        db = MagicMock()
        db.fetch_value.side_effect = RuntimeError("DB error")
        bl = TokenBlacklist(db=db)
        with caplog.at_level(logging.ERROR):
            result = bl.is_revoked("header.payload.unknown")
        assert result is False
        assert "checking memory" in caplog.text


class TestIsRevokedNoDb:
    """No DB, token in memory -> True."""

    def test_is_revoked_no_db_in_memory(self):
        bl = TokenBlacklist()
        bl._revoked["inmem"] = time.monotonic()
        assert bl.is_revoked("header.payload.inmem") is True


class TestIsRevokedNotRevoked:
    """No DB, token NOT in memory -> False."""

    def test_is_revoked_not_revoked(self):
        bl = TokenBlacklist()
        assert bl.is_revoked("header.payload.nope") is False


class TestCleanupDbSuccess:
    """DB delete returns count, also cleans memory."""

    def test_cleanup_db_success(self):
        db = MagicMock()
        db.execute.return_value = 5
        bl = TokenBlacklist(db=db)
        result = bl.cleanup(3600)
        db.execute.assert_called_once()
        args, _ = db.execute.call_args
        assert "DELETE FROM admin.token_blacklist" in args[0]
        assert result >= 5

    def test_cleanup_db_success_and_memory_expired(self):
        db = MagicMock()
        db.execute.return_value = 3
        bl = TokenBlacklist(db=db)
        # Add an old memory entry that should be cleaned
        bl._revoked["oldsig"] = time.monotonic() - 7200
        result = bl.cleanup(3600)
        assert "oldsig" not in bl._revoked
        assert result >= 3


class TestCleanupDbException:
    """DB delete raises -> still cleans memory, logged."""

    def test_cleanup_db_exception_still_cleans_memory(self, caplog):
        db = MagicMock()
        db.execute.side_effect = RuntimeError("DB error")
        bl = TokenBlacklist(db=db)
        bl._revoked["oldsig"] = time.monotonic() - 7200
        with caplog.at_level(logging.ERROR):
            result = bl.cleanup(3600)
        assert "oldsig" not in bl._revoked
        assert "Failed to clean up DB token blacklist" in caplog.text

    def test_cleanup_db_exception_keeps_fresh_memory_entries(self, caplog):
        db = MagicMock()
        db.execute.side_effect = RuntimeError("DB error")
        bl = TokenBlacklist(db=db)
        bl._revoked["freshsig"] = time.monotonic()
        with caplog.at_level(logging.ERROR):
            bl.cleanup(3600)
        assert "freshsig" in bl._revoked


class TestCleanupExpiredMemoryEntries:
    """Memory entries older than cutoff are removed."""

    def test_cleanup_removes_expired_memory_entries(self):
        bl = TokenBlacklist()
        bl._revoked["old1"] = time.monotonic() - 5000
        bl._revoked["old2"] = time.monotonic() - 4000
        bl._revoked["fresh"] = time.monotonic()
        result = bl.cleanup(3600)
        assert "old1" not in bl._revoked
        assert "old2" not in bl._revoked
        assert "fresh" in bl._revoked
        assert result >= 2


class TestCleanupNoExpiredMemory:
    """No old entries -> removed count from DB only."""

    def test_cleanup_no_expired_memory_returns_db_count(self):
        db = MagicMock()
        db.execute.return_value = 7
        bl = TokenBlacklist(db=db)
        bl._revoked["fresh"] = time.monotonic()
        result = bl.cleanup(3600)
        assert "fresh" in bl._revoked
        assert result == 7

    def test_cleanup_no_db_no_expired_returns_zero(self):
        bl = TokenBlacklist()
        bl._revoked["fresh"] = time.monotonic()
        result = bl.cleanup(3600)
        assert result == 0
        assert "fresh" in bl._revoked


class TestExtractSignature:
    """Token with dots -> returns last segment; no dots -> returns full token."""

    def test_extract_signature_standard_jwt(self):
        sig = TokenBlacklist._extract_signature("header.payload.signature")
        assert sig == "signature"

    def test_extract_signature_multiple_dots(self):
        sig = TokenBlacklist._extract_signature("a.b.c.d.e")
        assert sig == "e"

    def test_extract_signature_single_dot(self):
        sig = TokenBlacklist._extract_signature("before.after")
        assert sig == "after"

    def test_extract_signature_no_dots(self):
        sig = TokenBlacklist._extract_signature("nodots")
        assert sig == "nodots"

    def test_extract_signature_empty_after_dot(self):
        sig = TokenBlacklist._extract_signature("something.")
        assert sig == ""
