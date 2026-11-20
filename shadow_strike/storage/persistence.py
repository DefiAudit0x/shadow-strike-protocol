"""Persist executed runs consistently across entry points.

Template promotion is intentionally manual: after reviewing and generalizing a
verified scenario (removing deployment addresses and target-specific assumptions),
a researcher calls store.add_library_entry(vulnerability_class, scenario_template,
tags=...). Verification alone does not establish that a scenario is reusable, so
this verified path saves the evidence but does not auto-promote raw scenarios.
"""

from __future__ import annotations

from contextlib import contextmanager

from shadow_strike.storage.db import KnowledgeStore


@contextmanager
def run_store(store=None, db_path="shadow_strike_knowledge.sqlite3"):
    """Use a caller's store, or own a durable SQLite connection for this run."""
    owned = store is None
    if owned:
        store = KnowledgeStore(db_path)
    try:
        yield store
    finally:
        if owned:
            store.close()


def save_run(store, scenario, execution_result, verdict, attempt_number=1, failure_reason=None):
    """Save the scenario and attempt, then attach proof only for a verified verdict.

    Generalized library entries are intentionally promoted manually; see the
    module docstring for the add_library_entry call site and review requirement.
    """
    store.save_scenario(scenario)
    attempt_id = store.save_attempt(
        scenario_id=scenario.scenario_id,
        attempt_number=attempt_number,
        status="success" if verdict is not None and verdict.verified else "failure",
        failure_reason=None if verdict is not None and verdict.verified else failure_reason,
        execution_result=execution_result.to_dict() if execution_result is not None else None,
        verifier_result=verdict.to_dict() if verdict is not None else None,
    )
    if verdict is not None and verdict.verified:
        store.save_proof(attempt_id=attempt_id, proof_artifact=verdict.proof_artifact)
    return attempt_id
