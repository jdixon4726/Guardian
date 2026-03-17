"""
Database Connection Abstraction

Wraps SQLite and PostgreSQL behind a common interface.
All Guardian stores use this instead of raw sqlite3.connect().

Design:
  - SQLite uses standard library sqlite3 (no extra dependencies)
  - PostgreSQL uses psycopg2 (optional dependency, only needed if configured)
  - Both expose the same DB-API 2.0 interface: execute, commit, fetchone, fetchall
  - Parameterized queries use '?' for SQLite and '%s' for Postgres
    (the connection auto-translates)
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class DatabaseConfig:
    """Database configuration — determines which backend to use."""
    backend: str = "sqlite"          # "sqlite" or "postgresql"
    # SQLite settings
    path: str = ":memory:"           # file path or ":memory:"
    # PostgreSQL settings (used when backend="postgresql")
    url: str = ""                    # postgresql://user:pass@host:port/db
    pool_size: int = 5
    # Shared settings
    pragma_wal: bool = True          # SQLite WAL mode
    autocommit: bool = False


class DatabaseConnection:
    """
    Database-agnostic connection wrapper.

    Provides execute(), commit(), fetchone(), fetchall() that work
    identically on SQLite and PostgreSQL.
    """

    def __init__(self, config: DatabaseConfig):
        self.config = config
        self._backend = config.backend
        self._conn: Any = None
        self._connect()

    def _connect(self) -> None:
        if self._backend == "sqlite":
            kwargs: dict[str, Any] = {"check_same_thread": False}
            if self.config.autocommit:
                kwargs["autocommit"] = True
            self._conn = sqlite3.connect(self.config.path, **kwargs)
            self._conn.row_factory = sqlite3.Row
            if self.config.pragma_wal:
                self._conn.execute("PRAGMA journal_mode=WAL")
            logger.info("SQLite connection: %s", self.config.path)

        elif self._backend == "postgresql":
            try:
                import psycopg2
                import psycopg2.extras
            except ImportError:
                raise ImportError(
                    "psycopg2 is required for PostgreSQL backend. "
                    "Install with: pip install psycopg2-binary"
                )
            self._conn = psycopg2.connect(
                self.config.url,
                cursor_factory=psycopg2.extras.RealDictCursor,
            )
            self._conn.autocommit = self.config.autocommit
            logger.info("PostgreSQL connection: %s", self.config.url.split("@")[-1] if "@" in self.config.url else "configured")

        else:
            raise ValueError(f"Unknown database backend: {self._backend}")

    def execute(self, sql: str, params: tuple | list = ()) -> Any:
        """Execute a SQL statement with parameter translation."""
        if self._backend == "postgresql":
            sql = sql.replace("?", "%s")
        cursor = self._conn.execute(sql, params)
        return cursor

    def executemany(self, sql: str, params_list: list) -> Any:
        if self._backend == "postgresql":
            sql = sql.replace("?", "%s")
        cursor = self._conn.cursor()
        cursor.executemany(sql, params_list)
        return cursor

    def executescript(self, sql: str) -> None:
        """Execute multiple SQL statements (for schema creation)."""
        if self._backend == "sqlite":
            self._conn.executescript(sql)
        else:
            # PostgreSQL: execute statements one at a time
            cursor = self._conn.cursor()
            for stmt in sql.split(";"):
                stmt = stmt.strip()
                if stmt:
                    # Translate SQLite-specific syntax
                    stmt = self._translate_schema(stmt)
                    cursor.execute(stmt)
            self._conn.commit()

    def commit(self) -> None:
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def fetchone(self, sql: str, params: tuple | list = ()) -> dict | None:
        """Execute and fetch one row as a dict."""
        cursor = self.execute(sql, params)
        row = cursor.fetchone()
        if row is None:
            return None
        if self._backend == "sqlite":
            return dict(row)
        return dict(row)  # psycopg2 RealDictCursor returns dict-like

    def fetchall(self, sql: str, params: tuple | list = ()) -> list[dict]:
        """Execute and fetch all rows as dicts."""
        cursor = self.execute(sql, params)
        rows = cursor.fetchall()
        if self._backend == "sqlite":
            return [dict(r) for r in rows]
        return [dict(r) for r in rows]

    @property
    def raw(self) -> Any:
        """Access the underlying connection (for advanced operations)."""
        return self._conn

    def _translate_schema(self, stmt: str) -> str:
        """Translate SQLite-specific DDL to PostgreSQL."""
        # INTEGER PRIMARY KEY AUTOINCREMENT → SERIAL PRIMARY KEY
        stmt = stmt.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
        # datetime('now') → NOW()
        stmt = stmt.replace("datetime('now')", "NOW()")
        # PRAGMA statements are SQLite-only
        if stmt.strip().upper().startswith("PRAGMA"):
            return "SELECT 1"  # no-op
        return stmt


def create_connection(config: DatabaseConfig | None = None) -> DatabaseConnection:
    """Factory function to create a database connection from config."""
    import os

    if config:
        return DatabaseConnection(config)

    # Auto-detect from environment
    pg_url = os.environ.get("GUARDIAN_DATABASE_URL", "")
    if pg_url:
        return DatabaseConnection(DatabaseConfig(
            backend="postgresql",
            url=pg_url,
            autocommit=False,
        ))

    # Default to SQLite
    return DatabaseConnection(DatabaseConfig(backend="sqlite", path=":memory:"))
