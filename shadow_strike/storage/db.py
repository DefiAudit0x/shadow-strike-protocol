"""
shadow_strike.storage.db
==========================
Knowledge Store, SQLite edition. Same four tables as the Postgres
schema in the architecture doc (scenarios, attempts, proofs,
attack_library_entries), using sqlite3 (stdlib — zero deps) so the
whole pipeline is runnable with nothing but a Python interpreter.

Swap to Postgres for production by pointing SQLAlchemy at the same
schema — the column set is intentionally identical so the migration
is a connection-string change, not a data-model change.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS scenarios (
    id TEXT PRIMARY KEY,
    vulnerability_class TEXT NOT NULL,
    target_protocol TEXT NOT NULL,
    scenario_json TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS attempts (
    id TEXT PRIMARY KEY,
    scenario_id TEXT NOT NULL REFERENCES scenarios(id),
    attempt_number INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('success','failure','error')),
    failure_reason TEXT,
    execution_result_json TEXT,
    verifier_result_json TEXT,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS proofs (
    id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES attempts(id),
    proof_artifact_json TEXT NOT NULL,
    broken_invariant TEXT,
    critical_transition TEXT,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS attack_library_entries (
    id TEXT PRIMARY KEY,
    vulnerability_class TEXT NOT NULL,
    scenario_template_json TEXT NOT NULL,
    success_rate REAL,
    tags TEXT,
    created_at REAL NOT NULL
);
"""


class KnowledgeStore:
    def __init__(self, db_path: str | Path = ":memory:"):
        self.db_path = str(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ---- scenarios --------------------------------------------------
    def save_scenario(self, scenario) -> str:
        self.conn.execute(
            "INSERT OR REPLACE INTO scenarios (id, vulnerability_class, target_protocol, scenario_json, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                scenario.scenario_id,
                scenario.vulnerability_class.value,
                scenario.target_protocol,
                scenario.to_json(),
                time.time(),
            ),
        )
        self.conn.commit()
        return scenario.scenario_id

    # ---- attempts -----------------------------------------------------
    def save_attempt(
        self,
        scenario_id: str,
        attempt_number: int,
        status: str,
        failure_reason: str | None,
        execution_result: dict | None,
        verifier_result: dict | None,
    ) -> str:
        attempt_id = f"att_{uuid.uuid4().hex[:10]}"
        self.conn.execute(
            "INSERT INTO attempts (id, scenario_id, attempt_number, status, failure_reason, "
            "execution_result_json, verifier_result_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                attempt_id,
                scenario_id,
                attempt_number,
                status,
                failure_reason,
                json.dumps(execution_result, default=str) if execution_result else None,
                json.dumps(verifier_result, default=str) if verifier_result else None,
                time.time(),
            ),
        )
        self.conn.commit()
        return attempt_id

    def attempts_for_scenario(self, scenario_id: str) -> list[sqlite3.Row]:
        cur = self.conn.execute(
            "SELECT * FROM attempts WHERE scenario_id = ? ORDER BY attempt_number", (scenario_id,)
        )
        return cur.fetchall()

    # ---- proofs -------------------------------------------------------
    def save_proof(
        self,
        attempt_id: str,
        proof_artifact: dict,
        broken_invariant: str | None = None,
        critical_transition: str | None = None,
    ) -> str:
        proof_id = f"proof_{uuid.uuid4().hex[:10]}"
        self.conn.execute(
            "INSERT INTO proofs (id, attempt_id, proof_artifact_json, broken_invariant, "
            "critical_transition, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                proof_id,
                attempt_id,
                json.dumps(proof_artifact, default=str),
                broken_invariant,
                critical_transition,
                time.time(),
            ),
        )
        self.conn.commit()
        return proof_id

    # ---- attack library (generalized, reusable templates) -------------
    def add_library_entry(self, vulnerability_class: str, scenario_template: dict, tags: list[str] | None = None) -> str:
        entry_id = f"lib_{uuid.uuid4().hex[:10]}"
        self.conn.execute(
            "INSERT INTO attack_library_entries (id, vulnerability_class, scenario_template_json, "
            "success_rate, tags, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                entry_id,
                vulnerability_class,
                json.dumps(scenario_template, default=str),
                None,
                json.dumps(tags or []),
                time.time(),
            ),
        )
        self.conn.commit()
        return entry_id

    def library_entries(self, vulnerability_class: str | None = None) -> list[sqlite3.Row]:
        if vulnerability_class:
            cur = self.conn.execute(
                "SELECT * FROM attack_library_entries WHERE vulnerability_class = ? ORDER BY created_at DESC",
                (vulnerability_class,),
            )
        else:
            cur = self.conn.execute("SELECT * FROM attack_library_entries ORDER BY created_at DESC")
        return cur.fetchall()

    def close(self):
        self.conn.close()
