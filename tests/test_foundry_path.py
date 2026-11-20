"""Production dispatch regression tests using a real, offline stub forge process.

The stub checks the generated file and emits Forge-shaped JSON. It does
not compile Solidity or establish EVM correctness (covered by later parts).
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from shadow_strike.agent.graph_simple import SimpleShadowStrikeGraph
from shadow_strike.agent.nodes import executor_node, scenario_planner_node
from shadow_strike.benchmark.runner import run_benchmark
from shadow_strike.core.models import ExecutionResult
from shadow_strike.execution.foundry_runner import ForgeRunner
from shadow_strike.integrations.axiom_adapter import SentinelHypothesisRequest, handle_sentinel_request
from shadow_strike.storage.db import KnowledgeStore

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'function withdraw() external { msg.sender.call{value: 1}(""); }'
TARGETS = {"vault": "0x1111111111111111111111111111111111111111"}
STUB = '''#!/usr/bin/env python3
import json
from pathlib import Path
import sys
args = sys.argv[1:]
assert args[0] == "test", args
contract = args[args.index("--match-contract") + 1]
path = Path(args[args.index("--match-path") + 1])
assert path.is_file(), path
source = path.read_text()
assert path.name == contract + ".t.sol", path
assert "contract " + contract + " is Test" in source
assert "function test_" in source
with Path("forge-invocations.jsonl").open("a") as log:
    log.write(json.dumps({"path": str(path), "contract": contract}) + "\\n")
print(json.dumps({str(path): {"test_results": {"test_scenario()": {
    "success": True,
    "decoded_logs": ["attacker_eth_before: 1000000000000000000", "attacker_eth_after: 11000000000000000000",
                     "vault_eth_before: 10000000000000000000", "vault_eth_after: 0",
                     "vault_slots_written: 1", "vault_written_slot: 0x01",
                     "ss.attacker.address: 0x2222222222222222222222222222222222222222",
                     "ss.vault.owner: 0x2222222222222222222222222222222222222222",
                     "ss.vault.last_caller: 0x2222222222222222222222222222222222222222",
                     "ss.vault.replay_count: 2", "ss.vault.victim_shares: 0",
                     "ss.attacker.legitimate_entitlement: 1000000000000000000"]
}}}}))
'''


class TestFoundryProductionPath(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        binary_dir = self.root / "bin"
        binary_dir.mkdir()
        forge = binary_dir / "forge"
        forge.write_text(STUB)
        forge.chmod(0o755)
        env = patch.dict(os.environ, {"PATH": str(binary_dir) + os.pathsep + os.environ["PATH"]})
        env.start()
        self.addCleanup(env.stop)
        self.executor = ForgeRunner(self.root)

    def assert_forge_ran(self):
        calls = [json.loads(line) for line in (self.root / "forge-invocations.jsonl").read_text().splitlines()]
        self.assertGreater(len(calls), 0)
        for call in calls:
            self.assertTrue((self.root / call["path"]).is_file())
        return calls

    def test_simple_graph_compiles_runs_and_populates_execution_result(self):
        state = SimpleShadowStrikeGraph(self.executor, max_retries=0).run(
            SOURCE, "Foundry regression", "https://example.invalid/rpc", 1, TARGETS,
        )
        result = state["execution_result"]
        self.assertIsInstance(result, ExecutionResult)
        self.assertEqual(result.scenario_id, state["current_scenario"].scenario_id)
        self.assertEqual(result.engine, "foundry")
        self.assertFalse(result.reverted)
        self.assertEqual(result.state_vars["attacker"]["eth_balance_after"], 11)
        self.assertEqual(result.state_diff["vault"]["written_slots"], ["0x01"])
        self.assertTrue(result.raw_logs)
        self.assertEqual(result.state_vars["vault"]["owner"], "attacker")
        self.assertEqual(result.state_vars["vault"]["last_caller"], "attacker")
        self.assertEqual(result.state_vars["vault"]["replay_count"], 2)
        self.assertEqual(result.state_vars["vault"]["victim_shares"], 0)
        self.assertEqual(result.state_vars["attacker"]["legitimate_entitlement"], 1)
        self.assertIsNotNone(state["verifier_verdict"])
        self.assertEqual(len(self.assert_forge_ran()), 1)

    def test_executor_node_without_scenario_does_not_invoke_forge(self):
        self.assertIsNone(executor_node({"current_scenario": None}, self.executor)["execution_result"])
        self.assertFalse((self.root / "forge-invocations.jsonl").exists())

    def test_executor_node_compiles_and_runs_forge_runner(self):
        state = scenario_planner_node(
            {"hypotheses": [{"vulnerability_class": "reentrancy", "hypothesis": SOURCE}]},
            fork_url="", fork_block=0, target_contracts=TARGETS,
        )
        scenario = state["current_scenario"]
        self.assertIsNotNone(scenario)
        with patch.object(self.executor, "run", wraps=self.executor.run) as run:
            result = executor_node(state, self.executor)["execution_result"]
        run.assert_called_once()
        executed_scenario, test_file = run.call_args.args
        self.assertIs(executed_scenario, scenario)
        self.assertTrue(Path(test_file).is_file())
        self.assertIsInstance(result, ExecutionResult)
        self.assertEqual(result.scenario_id, scenario.scenario_id)
        self.assertEqual(result.engine, "foundry")
        self.assertFalse(result.reverted)
        self.assertEqual(result.state_vars["attacker"]["eth_balance_after"], 11)
        self.assertEqual(len(self.assert_forge_ran()), 1)

    def test_benchmark_compiles_and_runs_foundry_scenario(self):
        report = run_benchmark(SOURCE, "Foundry benchmark", TARGETS, {"reentrancy": self.executor})
        self.assertEqual(len(report.results), 1)
        self.assertIn(report.results[0].status, ("exploitable", "resisted"))
        self.assertEqual(len(self.assert_forge_ran()), 1)

    def test_axiom_targeted_and_full_benchmark_paths(self):
        for suspected in ("reentrancy", None):
            with self.subTest(suspected=suspected):
                response = handle_sentinel_request(
                    SentinelHypothesisRequest("foundry-test", "Foundry adapter", SOURCE, TARGETS,
                                              suspected_vulnerability_class=suspected),
                    {"reentrancy": self.executor},
                )
                self.assertEqual(response.request_id, "foundry-test")
                self.assertEqual(len(response.tested_classes), 1)
                self.assertIn(response.tested_classes[0]["status"], ("exploitable", "resisted"))
        self.assertEqual(len(self.assert_forge_ran()), 2)

    def test_cli_run_engine_foundry(self):
        source = self.root / "Vault.sol"
        source.write_text(SOURCE)
        proc = subprocess.run(
            [sys.executable, "-m", "shadow_strike.cli", "run", "--engine", "foundry",
             "--source", str(source), "--protocol", "Foundry CLI", "--target", "vault=" + TARGETS["vault"],
             "--foundry-root", str(self.root), "--db", str(self.root / "cli.sqlite3"), "--max-retries", "0"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("ATTACK VERIFIED", proc.stdout)
        self.assertIn("[verifier]", proc.stderr)
        calls = self.assert_forge_ran()
        scenario_id = calls[0]["contract"].removeprefix("ShadowStrike_")
        store = KnowledgeStore(str(self.root / "cli.sqlite3"))
        self.addCleanup(store.close)
        attempt = store.attempts_for_scenario(scenario_id)[0]
        result = json.loads(attempt["execution_result_json"])
        self.assertEqual(result["engine"], "foundry")
        self.assertEqual(result["state_vars"]["attacker"]["eth_balance_after"], 11)

    @unittest.skipUnless(importlib.util.find_spec("fastapi") and importlib.util.find_spec("httpx"),
                         "API regression requires optional fastapi and httpx dependencies")
    def test_post_runs_engine_foundry(self):
        import httpx

        api_store = KnowledgeStore(self.root / "api.sqlite3")
        self.addCleanup(api_store.close)
        environment = patch.dict(os.environ, {
            "SHADOW_STRIKE_API_TOKEN": "foundry-test-token",
            "SHADOW_STRIKE_DB_PATH": str(self.root / "api.sqlite3"),
        })
        environment.start()
        self.addCleanup(environment.stop)
        previous_cwd = Path.cwd()
        try:
            os.chdir(self.root)
            from shadow_strike.api import main as api
            async def run_api_job():
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=api.app), base_url="http://test",
                ) as client:
                    response = await client.post("/runs", json={
                        "source_code": SOURCE, "protocol_name": "Foundry API", "target_contracts": TARGETS,
                        "engine": "foundry", "max_retries": 0,
                    }, headers={"Authorization": "Bearer foundry-test-token"})
                    self.assertEqual(response.status_code, 202, response.text)
                    job_id = response.json()["job_id"]
                    for _ in range(100):
                        job = await client.get(
                            f"/jobs/{job_id}", headers={"Authorization": "Bearer foundry-test-token"},
                        )
                        self.assertEqual(job.status_code, 200, job.text)
                        if job.json()["status"] in ("complete", "failed"):
                            break
                        await asyncio.sleep(0.01)
                    self.assertEqual(job.json()["status"], "complete", job.text)
                    return job.json()["result"]

            payload = asyncio.run(run_api_job())
        finally:
            os.chdir(previous_cwd)
        self.assertTrue(payload["scenario_id"])
        self.assertIn("stopped_reason", payload)
        self.assertIsNotNone(api_store.conn.execute(
            "SELECT id FROM scenarios WHERE id = ?", (payload["scenario_id"],),
        ).fetchone())
        self.assertEqual(len(self.assert_forge_ran()), 1)


if __name__ == "__main__":
    unittest.main()
