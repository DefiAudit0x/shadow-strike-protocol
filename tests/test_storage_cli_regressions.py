import json
import sqlite3
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from shadow_strike import cli
from shadow_strike.core.models import VerificationResult
from shadow_strike.storage.db import KnowledgeStore
from shadow_strike.storage.persistence import save_run


def definition(protocol="Example"):
    return SimpleNamespace(
        scenario_id="scenario",
        target_protocol=protocol,
        vulnerability_class=SimpleNamespace(value="accounting"),
        to_json=lambda **kwargs: json.dumps({"target_protocol": protocol}, **kwargs),
    )


@pytest.fixture
def store():
    db = KnowledgeStore()
    try:
        yield db
    finally:
        db.close()


def test_foreign_keys_reject_orphans(store):
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        store.save_attempt("missing", 1, "failure", None, None, None)
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        store.save_proof("missing", {})


def test_scenario_upsert_preserves_row_and_attempt(store):
    scenario = definition()
    store.save_scenario(scenario)
    rowid = store.conn.execute("SELECT rowid FROM scenarios").fetchone()[0]
    store.save_scenario(definition("Updated"))
    assert store.conn.execute("SELECT rowid, target_protocol FROM scenarios").fetchone()[:] == (
        rowid, "Updated",
    )
    attempt = store.save_attempt(scenario.scenario_id, 1, "failure", None, None, None)
    store.save_scenario(definition("Updated"))
    assert [row["id"] for row in store.attempts_for_scenario(scenario.scenario_id)] == [attempt]


def test_scenario_with_attempts_rejects_definition_changes(store):
    scenario = definition()
    store.save_scenario(scenario)
    store.save_attempt(scenario.scenario_id, 1, "failure", None, None, None)
    assert store.save_scenario(definition()) == scenario.scenario_id
    with pytest.raises(ValueError, match="already has attempts"):
        store.save_scenario(definition("Changed"))
    assert store.get_scenario(scenario.scenario_id)["target_protocol"] == "Example"


def test_error_verdict_retains_error_status(store):
    scenario = definition()
    verdict = VerificationResult(scenario.scenario_id, False, [], [], {}, verdict="error")
    save_run(store, scenario, None, verdict, failure_reason="execution error")
    attempt, = store.attempts_for_scenario(scenario.scenario_id)
    assert (attempt["status"], attempt["failure_reason"]) == ("error", "execution error")
    assert store.list_proofs() == []


def test_postgres_scenario_upsert_preserves_attempts():
    pytest.importorskip("sqlalchemy")
    from shadow_strike.storage.postgres_store import PostgresKnowledgeStore

    store = PostgresKnowledgeStore("sqlite://")
    try:
        with store.engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys = ON")

        store.save_scenario(definition())
        store.save_scenario(definition("Updated"))
        attempt = store.save_attempt("scenario", 1, "failure", None, None, None)
        store.save_scenario(definition("Updated"))
        with pytest.raises(ValueError, match="already has attempts"):
            store.save_scenario(definition("Changed"))

        assert store.get_scenario("scenario")["target_protocol"] == "Updated"
        assert [row["id"] for row in store.attempts_for_scenario("scenario")] == [attempt]
    finally:
        store.close()


def test_postgres_list_proofs_returns_newest_first():
    pytest.importorskip("sqlalchemy")
    from shadow_strike.storage.postgres_store import PostgresKnowledgeStore, proofs_table

    store = PostgresKnowledgeStore("sqlite://")
    try:
        with store.engine.begin() as connection:
            connection.execute(proofs_table.insert(), [
                {"id": "older", "attempt_id": "a", "proof_artifact_json": "{}", "created_at": 1},
                {"id": "newer", "attempt_id": "a", "proof_artifact_json": "{}", "created_at": 2},
            ])
        assert [row["id"] for row in store.list_proofs()] == ["newer", "older"]
    finally:
        store.close()


def test_export_uses_store_accessor(monkeypatch, tmp_path):
    store = SimpleNamespace(get_scenario=Mock(return_value={"scenario_json": "{}"}), close=Mock())
    monkeypatch.setattr("shadow_strike.storage.persistence.KnowledgeStore", lambda _: store)
    scenario = object()
    monkeypatch.setattr(cli.AttackScenario, "from_json", Mock(return_value=scenario))
    export = Mock()
    monkeypatch.setattr(cli, "save_scenario_yaml", export)
    out = tmp_path / "scenario.yaml"

    cli.cmd_save_scenario(SimpleNamespace(db="db", scenario_id="scenario", out=out))

    store.get_scenario.assert_called_once_with("scenario")
    export.assert_called_once_with(scenario, out)


def test_mock_params_preserve_types():
    values = cli._parse_mock_params([
        "a:off=false", "a:count=3", "a:decimal=3.5", "a:on=TrUe", "a:plain=word",
        "a:n=null", "a:other=NONE", 'a:quoted="false"', "a:single='3'",
    ])["a"]
    expected = {
        "off": False, "count": 3, "decimal": 3.5, "on": True, "plain": "word",
        "n": None, "other": None, "quoted": "false", "single": "3",
    }
    assert values == expected
    assert {key: type(value) for key, value in values.items()} == {
        key: type(value) for key, value in expected.items()
    }


@pytest.mark.parametrize("bad_value", ["missing-shape", 'a:key="unterminated', "a:=value"])
def test_mock_params_cli_reports_invalid_input(monkeypatch, capsys, bad_value):
    scenario = SimpleNamespace(scenario_id="s", vulnerability_class=SimpleNamespace(value="accounting"))
    monkeypatch.setattr(cli, "load_scenario_yaml", lambda _: scenario)
    args = SimpleNamespace(file="scenario.yaml", engine="mock", mock_kinds=["a=Model"], mock_params=[bad_value])
    with pytest.raises(SystemExit) as exc:
        cli.cmd_run_scenario(args)
    assert exc.value.code == 2
    assert bad_value in capsys.readouterr().err


def test_history_closes_owned_store(monkeypatch, capsys):
    store = Mock()
    store.attempts_for_scenario.return_value = [{"status": "failure"}]
    monkeypatch.setattr("shadow_strike.storage.persistence.KnowledgeStore", lambda _: store)
    cli.cmd_history(SimpleNamespace(db="db", scenario_id="scenario"))
    store.close.assert_called_once_with()
    assert "failure" in capsys.readouterr().out


def test_retry_history_persists_every_attempt(tmp_path):
    """S03: a resisting SafeVault makes the graph execute 4 times; all
    four attempts must be persisted (one row each, under each attempt's
    own scenario), not just the final one."""
    from shadow_strike.agent.graph_simple import SimpleShadowStrikeGraph
    from shadow_strike.attack_library.registry import AttackLibrary
    from shadow_strike.execution.mock_executor import MockExecutor
    from shadow_strike.storage.persistence import run_store
    from shadow_strike.verifier.verifier import Verifier

    source = (
        "contract Vault {\n"
        "    function withdraw() external {\n"
        "        (bool ok,) = msg.sender.call{value: 1}(\"\");\n"
        "    }\n"
        "}\n"
    )
    executor = MockExecutor(contract_kinds={"vault": "SafeVault", "attacker": "ReentrantAttacker"})
    graph = SimpleShadowStrikeGraph(
        executor=executor, verifier=Verifier(), library=AttackLibrary(), max_retries=3,
    )
    result = graph.run(
        target_contract_source=source, target_protocol_name="InlineTestVault",
        fork_url="", fork_block=0, target_contracts={"vault": "0xdead"}, attacker_initial_eth=1.0,
    )
    assert result["attempt_count"] == 4
    records = result["attempt_records"]
    assert [record["attempt_number"] for record in records] == [1, 2, 3, 4]
    # The planner builds a fresh scenario per retry, so each record
    # carries its own scenario id.
    assert len({record["scenario"].scenario_id for record in records}) == 4

    scenario = result["current_scenario"]
    with run_store(db_path=str(tmp_path / "history.sqlite3")) as store:
        save_run(
            store, scenario, result.get("execution_result"), result.get("verifier_verdict"),
            attempt_number=result["attempt_count"], failure_reason=result["stopped_reason"],
            attempts=records,
        )
        rows = []
        for record in records:
            rows.extend(store.attempts_for_scenario(record["scenario"].scenario_id))
            assert store.get_scenario(record["scenario"].scenario_id) is not None
    assert len(rows) == 4
    assert sorted(row["attempt_number"] for row in rows) == [1, 2, 3, 4]
    assert {row["status"] for row in rows} == {"failure"}


def _ordered_scenario():
    """A scenario whose target_contracts define vault as the primary
    target (first key) — CodeRabbit (PR #32): sort_keys=True reordered
    them on disk, flipping the primary target."""
    return SimpleNamespace(
        scenario_id="ordered",
        target_protocol="Example",
        vulnerability_class=SimpleNamespace(value="reentrancy"),
        to_json=lambda **kwargs: json.dumps(
            {"initial_state": {"target_contracts": {"vault": "0x1", "aux": "0x2"}}}, **kwargs),
    )


def test_stored_scenario_preserves_target_order(store):
    store.save_scenario(_ordered_scenario())
    stored = json.loads(store.get_scenario("ordered")["scenario_json"])
    assert list(stored["initial_state"]["target_contracts"]) == ["vault", "aux"]


def test_postgres_stored_scenario_preserves_target_order():
    pytest.importorskip("sqlalchemy")
    from shadow_strike.storage.postgres_store import PostgresKnowledgeStore

    store = PostgresKnowledgeStore("sqlite://")
    try:
        store.save_scenario(_ordered_scenario())
        stored = json.loads(store.get_scenario("ordered")["scenario_json"])
        assert list(stored["initial_state"]["target_contracts"]) == ["vault", "aux"]
    finally:
        store.close()
