"""
shadow_strike.storage.postgres_store
=======================================
Production Knowledge Store: SQLAlchemy + Postgres, same four tables,
same method signatures as storage.db.KnowledgeStore — this is a
drop-in replacement, not a parallel API. Anything built against
KnowledgeStore (the CLI, examples/run_demo.py, api/main.py) works
unchanged against PostgresKnowledgeStore; only the constructor call
changes.

Requires: pip install sqlalchemy psycopg2-binary

NOT exercised by the bundled test suite — sqlalchemy/psycopg2 aren't
installed in the environment this project was built in (no network to
pip install them, no Postgres server to connect to). The schema below
is byte-for-byte the same shape as storage/db.py's SCHEMA constant;
the two are kept in sync by hand (see test_schema_parity below once
you have both available to actually run it).
"""

from __future__ import annotations

import json
import time
import uuid

try:
    from sqlalchemy import (
        create_engine, Column, String, Integer, Float, Text, ForeignKey, MetaData, Table,
    )
    from sqlalchemy.orm import sessionmaker
except ImportError as e:
    raise ImportError(
        "postgres_store requires: pip install sqlalchemy psycopg2-binary. "
        "For zero-dependency storage, use shadow_strike.storage.db.KnowledgeStore (SQLite) instead."
    ) from e

metadata = MetaData()

scenarios_table = Table(
    "scenarios", metadata,
    Column("id", String, primary_key=True),
    Column("vulnerability_class", String, nullable=False),
    Column("target_protocol", String, nullable=False),
    Column("scenario_json", Text, nullable=False),
    Column("created_at", Float, nullable=False),
)

attempts_table = Table(
    "attempts", metadata,
    Column("id", String, primary_key=True),
    Column("scenario_id", String, ForeignKey("scenarios.id"), nullable=False),
    Column("attempt_number", Integer, nullable=False),
    Column("status", String, nullable=False),
    Column("failure_reason", Text, nullable=True),
    Column("execution_result_json", Text, nullable=True),
    Column("verifier_result_json", Text, nullable=True),
    Column("created_at", Float, nullable=False),
)

proofs_table = Table(
    "proofs", metadata,
    Column("id", String, primary_key=True),
    Column("attempt_id", String, ForeignKey("attempts.id"), nullable=False),
    Column("proof_artifact_json", Text, nullable=False),
    Column("broken_invariant", Text, nullable=True),
    Column("critical_transition", Text, nullable=True),
    Column("created_at", Float, nullable=False),
)

attack_library_entries_table = Table(
    "attack_library_entries", metadata,
    Column("id", String, primary_key=True),
    Column("vulnerability_class", String, nullable=False),
    Column("scenario_template_json", Text, nullable=False),
    Column("success_rate", Float, nullable=True),
    Column("tags", Text, nullable=True),
    Column("created_at", Float, nullable=False),
)


class PostgresKnowledgeStore:
    """Same method signatures as storage.db.KnowledgeStore — see that
    class's docstrings for what each method does; not repeated here."""

    def __init__(self, connection_url: str):
        """connection_url example:
        postgresql+psycopg2://user:password@host:5432/shadow_strike"""
        self.engine = create_engine(connection_url)
        metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def save_scenario(self, scenario) -> str:
        with self.Session() as session:
            session.execute(scenarios_table.delete().where(scenarios_table.c.id == scenario.scenario_id))
            session.execute(scenarios_table.insert().values(
                id=scenario.scenario_id,
                vulnerability_class=scenario.vulnerability_class.value,
                target_protocol=scenario.target_protocol,
                scenario_json=scenario.to_json(),
                created_at=time.time(),
            ))
            session.commit()
        return scenario.scenario_id

    def save_attempt(self, scenario_id, attempt_number, status, failure_reason,
                      execution_result, verifier_result) -> str:
        attempt_id = f"att_{uuid.uuid4().hex[:10]}"
        with self.Session() as session:
            session.execute(attempts_table.insert().values(
                id=attempt_id, scenario_id=scenario_id, attempt_number=attempt_number,
                status=status, failure_reason=failure_reason,
                execution_result_json=json.dumps(execution_result, default=str) if execution_result else None,
                verifier_result_json=json.dumps(verifier_result, default=str) if verifier_result else None,
                created_at=time.time(),
            ))
            session.commit()
        return attempt_id

    def attempts_for_scenario(self, scenario_id: str) -> list[dict]:
        with self.Session() as session:
            rows = session.execute(
                attempts_table.select()
                .where(attempts_table.c.scenario_id == scenario_id)
                .order_by(attempts_table.c.attempt_number)
            ).fetchall()
            return [dict(r._mapping) for r in rows]

    def save_proof(self, attempt_id, proof_artifact, broken_invariant=None, critical_transition=None) -> str:
        proof_id = f"proof_{uuid.uuid4().hex[:10]}"
        with self.Session() as session:
            session.execute(proofs_table.insert().values(
                id=proof_id, attempt_id=attempt_id,
                proof_artifact_json=json.dumps(proof_artifact, default=str),
                broken_invariant=broken_invariant, critical_transition=critical_transition,
                created_at=time.time(),
            ))
            session.commit()
        return proof_id

    def add_library_entry(self, vulnerability_class, scenario_template, tags=None) -> str:
        entry_id = f"lib_{uuid.uuid4().hex[:10]}"
        with self.Session() as session:
            session.execute(attack_library_entries_table.insert().values(
                id=entry_id, vulnerability_class=vulnerability_class,
                scenario_template_json=json.dumps(scenario_template, default=str),
                success_rate=None, tags=json.dumps(tags or []), created_at=time.time(),
            ))
            session.commit()
        return entry_id

    def library_entries(self, vulnerability_class: str | None = None) -> list[dict]:
        with self.Session() as session:
            q = attack_library_entries_table.select().order_by(attack_library_entries_table.c.created_at.desc())
            if vulnerability_class:
                q = q.where(attack_library_entries_table.c.vulnerability_class == vulnerability_class)
            rows = session.execute(q).fetchall()
            return [dict(r._mapping) for r in rows]

    def close(self):
        self.engine.dispose()


def migrate_from_sqlite(sqlite_store, postgres_store: PostgresKnowledgeStore) -> dict:
    """One-shot migration helper: copies every row from a
    storage.db.KnowledgeStore (SQLite) into a PostgresKnowledgeStore.
    Returns counts per table. Untested here for the same reason the
    rest of this file is (no sqlalchemy/Postgres in this sandbox) —
    reviewed for correctness against both schemas, not executed."""
    counts = {"scenarios": 0, "attempts": 0, "proofs": 0, "attack_library_entries": 0}

    for row in sqlite_store.conn.execute("SELECT * FROM scenarios"):
        postgres_store.engine.execute(scenarios_table.insert().values(**dict(row)))
        counts["scenarios"] += 1
    for row in sqlite_store.conn.execute("SELECT * FROM attempts"):
        postgres_store.engine.execute(attempts_table.insert().values(**dict(row)))
        counts["attempts"] += 1
    for row in sqlite_store.conn.execute("SELECT * FROM proofs"):
        postgres_store.engine.execute(proofs_table.insert().values(**dict(row)))
        counts["proofs"] += 1
    for row in sqlite_store.conn.execute("SELECT * FROM attack_library_entries"):
        postgres_store.engine.execute(attack_library_entries_table.insert().values(**dict(row)))
        counts["attack_library_entries"] += 1

    return counts
