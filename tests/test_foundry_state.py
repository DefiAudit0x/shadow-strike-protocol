"""State protocol tests; no generated Solidity is executed."""
import json
import subprocess
import unittest

from test_pipeline import _make_scenario

from shadow_strike.core.safe_eval import safe_eval
from shadow_strike.execution.compiler import ScenarioCompiler
from shadow_strike.execution.foundry_runner import ForgeRunner
from shadow_strike.execution.mock_executor import MockExecutor


class TestFoundryState(unittest.TestCase):
    def parse(self, scenario, lines):
        runner = object.__new__(ForgeRunner)
        proc = subprocess.CompletedProcess([], 0, json.dumps({"reference": {"test_results": {
            "test_state()": {"success": True, "decoded_logs": lines},
        }}}), "")
        return runner._parse_result(scenario, proc)

    def test_state_fields_and_addresses(self):
        scenario = _make_scenario()
        address = "0x" + "aB" * 20
        result = self.parse(scenario, [
            f"ss.attacker.address: {address}", f"ss.vault.owner: {address.lower()}",
            f"ss.vault.last_caller: {address}", "ss.vault.replay_count: 2",
            "ss.vault.victim_shares: 0", "ss.token.attacker_balance: 123",
            "ss.attacker.legitimate_entitlement: 1000000000000000000",
        ])
        self.assertEqual(result.state_vars["vault"], {
            "owner": "attacker", "last_caller": "attacker", "replay_count": 2, "victim_shares": 0,
        })
        self.assertEqual(result.state_vars["token"]["attacker_balance"], 123)
        self.assertEqual(result.state_vars["attacker"]["legitimate_entitlement"], 1)
        self.assertNotIn("gas_used", result.to_dict())
        self.assertNotIn("missing", result.state_vars)

    def test_same_reentrancy_condition_and_units(self):
        scenario = _make_scenario()
        expression = scenario.success_conditions[0].expression
        # Stub Forge observations of the existing scenario, in native wei.
        # Check both profitable and unprofitable outcomes at the units boundary.
        for kind in ("VulnerableVault", "SafeVault"):
            mock = MockExecutor(contract_kinds={"vault": kind, "attacker": "ReentrantAttacker"}).execute(scenario)
            after_wei = 3700000000000000000 if kind == "VulnerableVault" else 1000000000000000000
            foundry = self.parse(scenario, [
                "attacker_eth_before: 1000000000000000000",
                f"attacker_eth_after: {after_wei}",
                "ss.attacker.legitimate_entitlement: 1000000000000000000",
            ])
            self.assertEqual(safe_eval(expression, mock.state_vars), safe_eval(expression, foundry.state_vars))
            self.assertEqual(safe_eval(expression, foundry.state_vars), kind == "VulnerableVault")
            for field, value in mock.state_vars["attacker"].items():
                self.assertAlmostEqual(value, foundry.state_vars["attacker"][field])

    def test_existing_scenario_emits_getters(self):
        scenario = _make_scenario()
        scenario.initial_state.target_contracts = {"vault": "0x" + "1" * 40}
        source = ScenarioCompiler().compile(scenario, attacker_contract_name="MaliciousReceiver_demo")
        for field in ("owner", "last_caller", "replay_count", "victim_shares"):
            self.assertIn(f'"ss.vault.{field}"', source)
        self.assertIn('"ss.attacker.legitimate_entitlement"', source)
        self.assertIn("target.staticcall", source)
