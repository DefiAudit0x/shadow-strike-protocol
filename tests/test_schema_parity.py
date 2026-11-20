"""SQLite/Postgres storage schema parity and SQLAlchemy 2 migration tests."""

from __future__ import annotations

import unittest
from contextlib import contextmanager
from unittest.mock import Mock

from shadow_strike.storage.db import KnowledgeStore

try:
    from shadow_strike.storage.postgres_store import (
        PostgresKnowledgeStore,
        attempts_table,
        metadata,
        migrate_from_sqlite,
    )
except ImportError:
    PostgresKnowledgeStore = None


@unittest.skipIf(PostgresKnowledgeStore is None, "SQLAlchemy is an optional production dependency")
class TestSchemaParity(unittest.TestCase):
    def test_schema_parity(self):
        sqlite = KnowledgeStore(":memory:")
        sqlite_tables = {
            row["name"]: row["sql"]
            for row in sqlite.conn.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        self.assertEqual(set(sqlite_tables), set(metadata.tables))

        for name, table in metadata.tables.items():
            sqlite_columns = {
                row["name"]: row["type"].upper()
                for row in sqlite.conn.execute(f"PRAGMA table_info({name})")
            }
            self.assertEqual(set(sqlite_columns), set(table.columns.keys()), name)
            for column in table.columns:
                if column.primary_key:
                    # SQLite's PRAGMA does not report the implicit NOT NULL
                    # of a PRIMARY KEY column, while SQLAlchemy defaults PKs
                    # to nullable=False; PK membership is asserted below.
                    continue
                self.assertEqual(column.nullable, not bool(
                    next(row["notnull"] for row in sqlite.conn.execute(f"PRAGMA table_info({name})")
                         if row["name"] == column.name)
                ), f"{name}.{column.name} nullability")
            sqlite_pk = {
                row["name"] for row in sqlite.conn.execute(f"PRAGMA table_info({name})") if row["pk"]
            }
            self.assertEqual(sqlite_pk, {column.name for column in table.primary_key.columns}, name)
            sqlite_fks = {
                (row["from"], row["table"], row["to"])
                for row in sqlite.conn.execute(f"PRAGMA foreign_key_list({name})")
            }
            postgres_fks = {
                (fk.parent.name, fk.column.table.name, fk.column.name) for fk in table.foreign_keys
            }
            self.assertEqual(sqlite_fks, postgres_fks, name)

        attempts_sql = sqlite_tables["attempts"]
        self.assertRegex(attempts_sql, r"CHECK\s*\(\s*status\s+IN\s*\('success','failure','error'\)\s*\)")
        self.assertEqual(len(attempts_table.constraints), 3)  # PK, FK, and status CHECK
        sqlite.close()

    def test_migrate_populated_sqlite_store_uses_connection_execute(self):
        sqlite = KnowledgeStore(":memory:")
        sqlite.conn.execute("INSERT INTO scenarios VALUES (?, ?, ?, ?, ?)",
                            ("s1", "reentrancy", "target", "{}", 1.0))
        sqlite.conn.execute("INSERT INTO attempts VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            ("a1", "s1", 1, "success", None, None, None, 2.0))
        sqlite.conn.execute("INSERT INTO proofs VALUES (?, ?, ?, ?, ?, ?)",
                            ("p1", "a1", "{}", None, None, 3.0))
        sqlite.conn.execute("INSERT INTO attack_library_entries VALUES (?, ?, ?, ?, ?, ?)",
                            ("l1", "reentrancy", "{}", None, "[]", 4.0))

        engine = Mock()
        connection = Mock()

        @contextmanager
        def begin():
            yield connection

        engine.begin.side_effect = begin
        store = Mock(engine=engine)
        counts = migrate_from_sqlite(sqlite, store)

        self.assertEqual(counts, {"scenarios": 1, "attempts": 1, "proofs": 1,
                                  "attack_library_entries": 1})
        self.assertEqual(connection.execute.call_count, 4)
        engine.execute.assert_not_called()
        sqlite.close()


if __name__ == "__main__":
    unittest.main()
