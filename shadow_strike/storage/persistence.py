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


def _attempt_status(verdict) -> str:
    """Canonical attempt status: an error verdict stays `error` (S05)."""
    if verdict is None:
        return "failure"
    if verdict.verdict == "error":
        return "error"
    return "success" if verdict.verified else "failure"


def _attempt_failure_reason(execution_result, verdict) -> str | None:
    """Per-attempt failure reason, derived the same way the critic
    classifies a failed attempt (S03)."""
    if verdict is not None and verdict.verified:
        return None
    if execution_result is not None and getattr(execution_result, "reverted", False):
        return getattr(execution_result, "revert_reason", None) or "reverted"
    return "success_conditions not met"


def _to_dict(value):
    if value is None:
        return None
    to_dict = getattr(value, "to_dict", None)
    return to_dict() if callable(to_dict) else value


def save_run(store, scenario, execution_result, verdict, attempt_number=1, failure_reason=None, attempts=None):
    """Save the scenario and attempt, then attach proof only for a verified verdict.

    Generalized library entries are intentionally promoted manually; see the
    module docstring for the add_library_entry call site and review requirement.

    When `attempts` is given (a list of per-attempt records as collected by
    the graph in `attempt_records`, each with `attempt_number`, `scenario`,
    `execution_result`, `verdict`), one attempt row is persisted per record
    (S03) — each under its own scenario, since the planner builds a fresh
    scenario per retry. Otherwise the historical single-attempt behavior
    applies (final attempt only).
    """
    store.save_scenario(scenario)
    if attempts:
        saved = []
        for record in attempts:
            record_scenario = record.get("scenario") or scenario
            record_verdict = record.get("verdict")
            record_execution = record.get("execution_result")
            status = _attempt_status(record_verdict)
            store.save_scenario(record_scenario)
            attempt_id = store.save_attempt(
                scenario_id=record_scenario.scenario_id,
                attempt_number=record.get("attempt_number", len(saved) + 1),
                status=status,
                failure_reason=None if status == "success"
                else _attempt_failure_reason(record_execution, record_verdict),
                execution_result=_to_dict(record_execution),
                verifier_result=_to_dict(record_verdict),
            )
            if status == "success" and record_verdict is not None:
                store.save_proof(attempt_id=attempt_id, proof_artifact=record_verdict.proof_artifact)
            saved.append(attempt_id)
        return saved[0]
    status = _attempt_status(verdict)
    attempt_id = store.save_attempt(
        scenario_id=scenario.scenario_id,
        attempt_number=attempt_number,
        status=status,
        failure_reason=None if status == "success" else failure_reason,
        execution_result=execution_result.to_dict() if execution_result is not None else None,
        verifier_result=verdict.to_dict() if verdict is not None else None,
    )
    if status == "success":
        store.save_proof(attempt_id=attempt_id, proof_artifact=verdict.proof_artifact)
    return attempt_id
