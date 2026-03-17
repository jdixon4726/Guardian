"""
Guardian Storage Abstraction Layer

Provides a database-agnostic connection interface so Guardian can
run on SQLite (development/demo) or PostgreSQL (production) via
a single configuration change.

Usage:
    from guardian.storage import create_connection, DatabaseConfig

    config = DatabaseConfig(backend="sqlite", path=":memory:")
    conn = create_connection(config)

    # Use standard DB-API 2.0 interface
    conn.execute("SELECT * FROM table WHERE id = ?", (1,))
    conn.commit()

To switch to Postgres, change config:
    config = DatabaseConfig(backend="postgresql", url="postgresql://...")
"""

from guardian.storage.connection import (
    DatabaseConfig,
    DatabaseConnection,
    create_connection,
)

__all__ = ["DatabaseConfig", "DatabaseConnection", "create_connection"]
