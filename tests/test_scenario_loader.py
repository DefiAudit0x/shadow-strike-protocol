"""Live proof of the hand-authoring workflow: YAML -> AttackScenario ->
full pipeline -> back to YAML, with zero network/extra deps."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from shadow_strike.core.scenario_loader import ScenarioFileError, load_scenario_yaml, save_scenario_yaml
from shadow_strike.execution.mock_executor import MockExecutor
from shadow_strike.verifier.verifier import Verifier

VALID_YAML = """
vulnerability_class: reentrancy
target_protocol: YamlTestVault
hypothesis: "test hypothesis from yaml"
attacker:
  initial_eth: 1.0
initial_state:
  fork_url: "https://example/rpc"
  fork_block: 1
  target_contracts:
    vault: "0xabc"
  balances:
    vault: 9.0
steps:
  - step_id: 1
    caller: attacker
    target: vault
    function: "deposit()"
    value_eth: 0.9
  - step_id: 2
    caller: attacker
    target: attacker
    function: "attack()"
success_conditions:
  - expression: "attacker.eth_balance_after - attacker.eth_balance_before > attacker.legitimate_entitlement"
    description: "profited"
"""

INVALID_YAML_NO_STEPS = """
vulnerability_class: reentrancy
target_protocol: X
hypothesis: "h"
initial_state:
  fork_url: "x"
  fork_block: 1
  target_contracts: {vault: "0xabc"}
steps: []
success_conditions:
  - expression: "1 > 0"
    description: "x"
"""


class TestScenarioLoader(unittest.TestCase):
    def test_loads_valid_yaml_and_runs_through_full_pipeline(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "scenario.yaml"
            p.write_text(VALID_YAML)
            scenario = load_scenario_yaml(p)

            executor = MockExecutor(contract_kinds={"vault": "VulnerableVault", "attacker": "ReentrantAttacker"})
            result = executor.execute(scenario)
            verdict = Verifier().verify(scenario, result)
            self.assertTrue(verdict.verified)

    def test_malformed_yaml_raises_scenario_file_error_not_raw_exception(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.yaml"
            p.write_text("this: is: not: valid: yaml: at: all: :::")
            with self.assertRaises(ScenarioFileError):
                load_scenario_yaml(p)

    def test_structurally_invalid_scenario_raises_scenario_file_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "empty_steps.yaml"
            p.write_text(INVALID_YAML_NO_STEPS)
            with self.assertRaises(ScenarioFileError):
                load_scenario_yaml(p)

    def test_roundtrip_yaml_export_reimport(self):
        with tempfile.TemporaryDirectory() as d:
            p1 = Path(d) / "a.yaml"
            p1.write_text(VALID_YAML)
            scenario = load_scenario_yaml(p1)

            p2 = Path(d) / "b.yaml"
            save_scenario_yaml(scenario, p2)
            reloaded = load_scenario_yaml(p2)

            self.assertEqual(reloaded.scenario_id, scenario.scenario_id)
            self.assertEqual(len(reloaded.steps), len(scenario.steps))


if __name__ == "__main__":
    unittest.main()
