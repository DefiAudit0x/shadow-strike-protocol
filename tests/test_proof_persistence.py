"""Part 11: real entry points persist evidence linked to successful attempts."""
from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from shadow_strike.benchmark.runner import run_benchmark
from shadow_strike.cli import main
from shadow_strike.execution.mock_executor import MockExecutor
from shadow_strike.integrations.axiom_adapter import SentinelHypothesisRequest, handle_sentinel_request
from shadow_strike.storage.db import KnowledgeStore

SOURCE = 'contract Vault { function withdraw() external { msg.sender.call{value: 1}(""); } }'


def executors(safe=False):
    return {"reentrancy": MockExecutor(contract_kinds={
        "vault": "SafeVault" if safe else "VulnerableVault", "attacker": "ReentrantAttacker",
    })}


class TestProofPersistence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "proofs.sqlite3"

    def assert_stored(self, expected=1):
        store = KnowledgeStore(self.db)
        self.addCleanup(store.close)
        proofs = store.list_proofs()
        self.assertEqual(len(proofs), expected)
        for proof in proofs:
            artifact = json.loads(proof["proof_artifact_json"])
            attempt = store.conn.execute("SELECT * FROM attempts WHERE id = ?", (proof["attempt_id"],)).fetchone()
            self.assertIsNotNone(attempt)
            self.assertEqual(attempt["status"], "success")
            self.assertEqual(attempt["scenario_id"], artifact["scenario"]["scenario_id"])
            self.assertEqual(json.loads(attempt["verifier_result_json"])["proof_artifact"], artifact)
            self.assertTrue(store.conn.execute(
                "SELECT 1 FROM scenarios WHERE id = ?", (attempt["scenario_id"],),
            ).fetchone())
        # Promotion is deliberately manual, rather than inserting deployment-specific scenarios.
        self.assertEqual(store.library_entries(), [])
        return store

    def run_cli(self, arguments, exit_code):
        with (
            patch("sys.argv", ["shadow-strike", *arguments, "--db", str(self.db)]),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            main()
        self.assertEqual(raised.exception.code, exit_code)

    def test_cli_verified_mock_run_leaves_proof(self):
        source = Path(self.tmp.name) / "Vault.sol"
        source.write_text(SOURCE)
        self.run_cli(["run", "--source", str(source), "--protocol", "Vault",
                      "--target", "vault=0xabc", "--engine", "mock"], 0)
        store = self.assert_stored()
        self.assertTrue(store.list_proofs())  # Part 11's explicit acceptance check.

    def test_cli_resisted_run_has_no_proof(self):
        source = Path(self.tmp.name) / "Vault.sol"
        source.write_text(SOURCE)
        self.run_cli(["run", "--source", str(source), "--protocol", "Vault",
                      "--target", "vault=0xabc", "--mock-kinds", "vault=SafeVault",
                      "--mock-kinds", "attacker=ReentrantAttacker"], 1)
        store = self.assert_stored(0)
        self.assertTrue(store.conn.execute("SELECT 1 FROM attempts").fetchone())

    def test_cli_run_scenario_saves_only_verified_proof(self):
        from shadow_strike.agent.graph_simple import SimpleShadowStrikeGraph
        from shadow_strike.core.scenario_loader import save_scenario_yaml

        result = SimpleShadowStrikeGraph(executor=executors()["reentrancy"]).run(
            SOURCE, "Vault", "", 0, {"vault": "0xabc"},
        )
        scenario_file = Path(self.tmp.name) / "scenario.yaml"
        save_scenario_yaml(result["current_scenario"], scenario_file)
        for safe in (False, True):
            self.run_cli(["run-scenario", "--file", str(scenario_file),
                          "--mock-kinds", f"vault={'SafeVault' if safe else 'VulnerableVault'}",
                          "--mock-kinds", "attacker=ReentrantAttacker"], 1 if safe else 0)
        self.assert_stored()

    def test_benchmark_persists_verified_but_not_resisted_proofs(self):
        store = KnowledgeStore(self.db)
        try:
            for safe in (False, True):
                report = run_benchmark(SOURCE, "Vault", {"vault": "0xabc"}, executors(safe), store=store)
                self.assertEqual(report.results[0].status, "resisted" if safe else "exploitable")
            self.assertEqual(len(store.list_proofs()), 1)  # caller-owned store stays open
        finally:
            store.close()
        self.assert_stored()

    def test_adapter_targeted_and_benchmark_persist_once_each(self):
        for suspected in ("reentrancy", None):
            for safe in (False, True):
                request = SentinelHypothesisRequest("r1", "Vault", SOURCE, {"vault": "0xabc"}, suspected)
                response = handle_sentinel_request(request, executors(safe), db_path=self.db)
                self.assertEqual(response.verified, not safe)
        self.assert_stored(2)

    def test_monitor_uses_its_store_without_duplicate_attempts(self):
        from shadow_strike.monitoring.watcher import ContinuousMonitor, DeploymentEvent

        store = KnowledgeStore(self.db)
        try:
            monitor = ContinuousMonitor(executors(), store=store)
            report = monitor.handle_event(DeploymentEvent("Vault", "0xabc", SOURCE, "deploy"))
            self.assertEqual(report.results[0].status, "exploitable")
            self.assertEqual(len(store.attempts_for_scenario(report.results[0].scenario_id)), 1)
        finally:
            store.close()
        self.assert_stored()

    def test_default_benchmark_and_adapter_store_is_durable(self):
        # Prove persistence is enabled without explicit store/db_path arguments.
        for run in (
            lambda: run_benchmark(SOURCE, "Vault", {"vault": "0xabc"}, executors()),
            lambda: handle_sentinel_request(
                SentinelHypothesisRequest("r", "Vault", SOURCE, {"vault": "0xabc"}, "reentrancy"), executors(),
            ),
        ):
            with patch("shadow_strike.storage.persistence.KnowledgeStore", wraps=KnowledgeStore) as factory:
                # Redirect the default file into this test's temporary directory.
                factory.side_effect = lambda path: KnowledgeStore(self.db)
                run()
                factory.assert_called_once_with("shadow_strike_knowledge.sqlite3")
        self.assert_stored(2)

    @unittest.skipUnless(importlib.util.find_spec("fastapi") and importlib.util.find_spec("httpx"),
                         "requires optional API dependencies")
    def test_api_routes_persist_to_configured_database(self):
        import httpx

        from shadow_strike.api import main as api

        payload = {"source_code": SOURCE, "protocol_name": "Vault", "target_contracts": {"vault": "0xabc"}}
        config = {"reentrancy": {"contract_kinds": {
            "vault": "VulnerableVault", "attacker": "ReentrantAttacker",
        }}}
        token = "proof-persistence-test"
        async def run_api_jobs():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=api.app), base_url="http://test",
            ) as client:
                async def run_job(path, body):
                    response = await client.post(
                        path, json=body, headers={"Authorization": f"Bearer {token}"},
                    )
                    self.assertEqual(response.status_code, 202, response.text)
                    job_id = response.json()["job_id"]
                    for _ in range(100):
                        status = await client.get(
                            f"/jobs/{job_id}", headers={"Authorization": f"Bearer {token}"},
                        )
                        self.assertEqual(status.status_code, 200, status.text)
                        if status.json()["status"] in ("complete", "failed"):
                            break
                        await asyncio.sleep(0.01)
                    self.assertEqual(status.json()["status"], "complete", status.text)
                    return status.json()["result"]

                result = await run_job("/runs", payload)
                self.assertTrue(result["verified"])
                result = await run_job("/benchmark", {**payload, "executor_config": config})
                self.assertEqual(result["results"][0]["status"], "exploitable")
                result = await run_job("/sentinel/hypothesis", {
                    "request_id": "r1", "target_protocol": "Vault", "source_code": SOURCE,
                    "target_contracts": {"vault": "0xabc"}, "executor_config": config,
                    "suspected_vulnerability_class": "reentrancy",
                })
                self.assertTrue(result["verified"])

        with patch.dict(os.environ, {
            "SHADOW_STRIKE_API_TOKEN": token,
            "SHADOW_STRIKE_DB_PATH": str(self.db),
        }):
            asyncio.run(run_api_jobs())
        self.assert_stored(3)


if __name__ == "__main__":
    unittest.main()
