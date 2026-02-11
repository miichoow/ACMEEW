"""Unit of Work — atomic multi-entity writes on a single transaction.

PyPGKit's :class:`BaseRepository` CRUD methods each acquire their own
connection from the pool, so multi-entity writes are not atomic.  This
wrapper provides explicit transaction control for operations that span
multiple tables.

Usage::

    from acmeeh.db import UnitOfWork

    db = Database.get_instance()
    with UnitOfWork(db) as uow:
        order_row = uow.insert("orders", {...})
        authz_row = uow.insert("authorizations", {...})
        uow.insert("order_authorizations", {...})
        # COMMIT on clean exit; ROLLBACK on exception
"""

from __future__ import annotations

from typing import Any, Self

from psycopg.rows import dict_row
from pypgkit import Database


class UnitOfWork:
    """Transaction-scoped helper for multi-table atomic writes.

    Wraps :meth:`Database.transaction` and exposes low-level SQL helpers
    that all operate on the **same connection** within a single
    transaction.  The caller is responsible for building correct SQL —
    this class is intentionally thin.
    """

    def __init__(self, database: Database | None = None) -> None:
        self._db = database or Database.get_instance()
        self._conn = None

    # -- context manager -----------------------------------------------------

    def __enter__(self) -> Self:
        self._tx = self._db.transaction()
        self._conn = self._tx.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._tx.__exit__(exc_type, exc_val, exc_tb)
        self._conn = None

    # -- helpers -------------------------------------------------------------

    def insert(self, table: str, row: dict[str, Any]) -> dict[str, Any]:
        """INSERT a single row and return the full row via RETURNING *.

        Parameters
        ----------
        table:
            Table name (unquoted).
        row:
            Column-name → value mapping.

        Returns
        -------
        dict
            The inserted row as returned by the database.

        """
        columns = list(row.keys())
        placeholders = ", ".join(["%s"] * len(columns))
        col_list = ", ".join(columns)
        sql = f"INSERT INTO {table} ({col_list}) VALUES ({placeholders}) RETURNING *"
        assert self._conn is not None, "UnitOfWork must be used as a context manager"
        with self._conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, list(row.values()))
            return cur.fetchone()

    def update_where(
        self,
        table: str,
        set_values: dict[str, Any],
        where: dict[str, Any],
    ) -> dict[str, Any] | None:
        """UPDATE rows matching *where* and return the first via RETURNING *.

        Parameters
        ----------
        table:
            Table name.
        set_values:
            Column → new-value pairs for the SET clause.
        where:
            Column → value pairs for the WHERE clause (AND-joined).

        Returns
        -------
        dict or None
            The updated row, or ``None`` if no row matched.

        """
        set_parts = [f"{col} = %s" for col in set_values]
        where_parts = [f"{col} = %s" for col in where]
        sql = (
            f"UPDATE {table} "
            f"SET {', '.join(set_parts)} "
            f"WHERE {' AND '.join(where_parts)} "
            f"RETURNING *"
        )
        params = list(set_values.values()) + list(where.values())
        assert self._conn is not None, "UnitOfWork must be used as a context manager"
        with self._conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params)
            return cur.fetchone()

    def execute(self, sql: str, params: tuple | list | None = None) -> int:
        """Execute arbitrary SQL and return the rowcount.

        Use for DELETE, custom UPDATE, or DDL statements.
        """
        assert self._conn is not None, "UnitOfWork must be used as a context manager"
        with self._conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.rowcount

    def fetch_one(
        self,
        sql: str,
        params: tuple | list | None = None,
    ) -> dict[str, Any] | None:
        """Execute a query and return the first row as a dict, or None."""
        assert self._conn is not None, "UnitOfWork must be used as a context manager"
        with self._conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params)
            return cur.fetchone()

    def fetch_all(
        self,
        sql: str,
        params: tuple | list | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a query and return all rows as dicts."""
        assert self._conn is not None, "UnitOfWork must be used as a context manager"
        with self._conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params)
            return cur.fetchall()
