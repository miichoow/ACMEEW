"""Unit tests for acmeeh.db.unit_of_work — UnitOfWork."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from acmeeh.db.unit_of_work import UnitOfWork

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_database():
    """Create a mock Database with transaction context manager support."""
    db = MagicMock()
    conn = MagicMock()
    tx = MagicMock()
    tx.__enter__ = MagicMock(return_value=conn)
    tx.__exit__ = MagicMock(return_value=False)
    db.transaction.return_value = tx
    return db, conn, tx


def _mock_cursor(return_value=None, fetchall_value=None, rowcount=1):
    """Create a mock cursor context manager."""
    cursor = MagicMock()
    cursor.fetchone.return_value = return_value
    cursor.fetchall.return_value = fetchall_value or []
    cursor.rowcount = rowcount
    cursor.__enter__ = MagicMock(return_value=cursor)
    cursor.__exit__ = MagicMock(return_value=False)
    return cursor


# ---------------------------------------------------------------------------
# Context manager behaviour
# ---------------------------------------------------------------------------


class TestContextManager:
    def test_enters_transaction_and_sets_connection(self):
        db, conn, tx = _mock_database()
        uow = UnitOfWork(db)

        with uow as ctx:
            assert ctx is uow
            assert uow._conn is conn

        db.transaction.assert_called_once()
        tx.__enter__.assert_called_once()

    def test_exit_clears_connection(self):
        db, conn, tx = _mock_database()
        uow = UnitOfWork(db)

        with uow:
            assert uow._conn is not None

        assert uow._conn is None
        tx.__exit__.assert_called_once()

    def test_exit_on_exception_clears_connection(self):
        db, conn, tx = _mock_database()
        uow = UnitOfWork(db)

        with pytest.raises(ValueError, match="test error"):
            with uow:
                raise ValueError("test error")

        assert uow._conn is None


# ---------------------------------------------------------------------------
# insert
# ---------------------------------------------------------------------------


class TestInsert:
    def test_builds_correct_sql_and_returns_row(self):
        db, conn, tx = _mock_database()
        expected_row = {"id": "abc-123", "name": "test", "value": 42}
        cursor = _mock_cursor(return_value=expected_row)
        conn.cursor.return_value = cursor

        uow = UnitOfWork(db)
        with uow:
            result = uow.insert("my_table", {"name": "test", "value": 42})

        assert result == expected_row
        # Verify the SQL structure
        execute_call = cursor.execute.call_args
        sql = execute_call[0][0]
        params = execute_call[0][1]
        assert "INSERT INTO my_table" in sql
        assert "name, value" in sql
        assert "VALUES (%s, %s)" in sql
        assert "RETURNING *" in sql
        assert params == ["test", 42]

    def test_raises_assertion_outside_context_manager(self):
        db, conn, tx = _mock_database()
        uow = UnitOfWork(db)

        with pytest.raises(AssertionError, match="context manager"):
            uow.insert("table", {"col": "val"})


# ---------------------------------------------------------------------------
# update_where
# ---------------------------------------------------------------------------


class TestUpdateWhere:
    def test_builds_correct_sql_and_returns_row(self):
        db, conn, tx = _mock_database()
        expected_row = {"id": "abc-123", "status": "active", "name": "updated"}
        cursor = _mock_cursor(return_value=expected_row)
        conn.cursor.return_value = cursor

        uow = UnitOfWork(db)
        with uow:
            result = uow.update_where(
                "orders",
                set_values={"status": "active", "name": "updated"},
                where={"id": "abc-123", "version": 1},
            )

        assert result == expected_row
        execute_call = cursor.execute.call_args
        sql = execute_call[0][0]
        params = execute_call[0][1]
        assert "UPDATE orders" in sql
        assert "SET" in sql
        assert "status = %s" in sql
        assert "name = %s" in sql
        assert "WHERE" in sql
        assert "id = %s" in sql
        assert "version = %s" in sql
        assert "RETURNING *" in sql
        # Params: SET values first, then WHERE values
        assert params == ["active", "updated", "abc-123", 1]

    def test_returns_none_when_no_match(self):
        db, conn, tx = _mock_database()
        cursor = _mock_cursor(return_value=None)
        conn.cursor.return_value = cursor

        uow = UnitOfWork(db)
        with uow:
            result = uow.update_where("orders", {"status": "x"}, {"id": "none"})

        assert result is None

    def test_raises_assertion_outside_context_manager(self):
        db, conn, tx = _mock_database()
        uow = UnitOfWork(db)

        with pytest.raises(AssertionError, match="context manager"):
            uow.update_where("table", {"col": "val"}, {"id": 1})


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------


class TestExecute:
    def test_runs_sql_and_returns_rowcount(self):
        db, conn, tx = _mock_database()
        cursor = _mock_cursor(rowcount=5)
        conn.cursor.return_value = cursor

        uow = UnitOfWork(db)
        with uow:
            result = uow.execute("DELETE FROM old_data WHERE age > %s", [90])

        assert result == 5
        cursor.execute.assert_called_once_with("DELETE FROM old_data WHERE age > %s", [90])

    def test_execute_without_params(self):
        db, conn, tx = _mock_database()
        cursor = _mock_cursor(rowcount=0)
        conn.cursor.return_value = cursor

        uow = UnitOfWork(db)
        with uow:
            result = uow.execute("TRUNCATE temp_table", None)

        assert result == 0
        cursor.execute.assert_called_once_with("TRUNCATE temp_table", None)

    def test_raises_assertion_outside_context_manager(self):
        db, conn, tx = _mock_database()
        uow = UnitOfWork(db)

        with pytest.raises(AssertionError, match="context manager"):
            uow.execute("SELECT 1")


# ---------------------------------------------------------------------------
# fetch_one
# ---------------------------------------------------------------------------


class TestFetchOne:
    def test_returns_dict(self):
        db, conn, tx = _mock_database()
        expected = {"id": 1, "name": "test"}
        cursor = _mock_cursor(return_value=expected)
        conn.cursor.return_value = cursor

        uow = UnitOfWork(db)
        with uow:
            result = uow.fetch_one("SELECT * FROM t WHERE id = %s", [1])

        assert result == expected

    def test_returns_none_when_no_row(self):
        db, conn, tx = _mock_database()
        cursor = _mock_cursor(return_value=None)
        conn.cursor.return_value = cursor

        uow = UnitOfWork(db)
        with uow:
            result = uow.fetch_one("SELECT * FROM t WHERE id = %s", [999])

        assert result is None

    def test_raises_assertion_outside_context_manager(self):
        db, conn, tx = _mock_database()
        uow = UnitOfWork(db)

        with pytest.raises(AssertionError, match="context manager"):
            uow.fetch_one("SELECT 1")


# ---------------------------------------------------------------------------
# fetch_all
# ---------------------------------------------------------------------------


class TestFetchAll:
    def test_returns_list_of_dicts(self):
        db, conn, tx = _mock_database()
        expected = [
            {"id": 1, "name": "a"},
            {"id": 2, "name": "b"},
            {"id": 3, "name": "c"},
        ]
        cursor = _mock_cursor(fetchall_value=expected)
        conn.cursor.return_value = cursor

        uow = UnitOfWork(db)
        with uow:
            result = uow.fetch_all("SELECT * FROM t ORDER BY id")

        assert result == expected
        assert len(result) == 3

    def test_returns_empty_list_when_no_rows(self):
        db, conn, tx = _mock_database()
        cursor = _mock_cursor(fetchall_value=[])
        conn.cursor.return_value = cursor

        uow = UnitOfWork(db)
        with uow:
            result = uow.fetch_all("SELECT * FROM t WHERE 1=0")

        assert result == []

    def test_raises_assertion_outside_context_manager(self):
        db, conn, tx = _mock_database()
        uow = UnitOfWork(db)

        with pytest.raises(AssertionError, match="context manager"):
            uow.fetch_all("SELECT 1")
