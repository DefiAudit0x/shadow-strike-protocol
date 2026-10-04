"""Live proof of the `accounting` class's hand-authoring path: a
concrete unchecked-arithmetic underflow bug, written by hand (no
automated builder exists for this class by design), run through the
same pipeline as every other scenario."""
from __future__ import annotations

import unittest
from pathlib import Path

from shadow_strike.core.scenario_loader import load_scenario_yaml
from shadow_strike.execution.mock_executor import MockExecutor
from shadow_strike.verifier.verifier import Verifier

SCENARIO_PATH = Path(__file__).parent.parent / "examples" / "scenarios" / "accounting_underflow_demo.yaml"


class TestAccountingUnderflow(unittest.TestCase):
    def test_unchecked_arithmetic_underflows_to_near_max_uint256(self):
        scenario = load_scenario_yaml(SCENARIO_PATH)
        executor = MockExecutor(contract_kinds={"token": "UncheckedBalanceToken"},
                                 contract_params={"token": {"checked": False}})
        result = executor.execute(scenario)
        verdict = Verifier().verify(scenario, result)

        self.assertFalse(result.reverted)
        self.assertTrue(verdict.verified)
        self.assertEqual(result.state_vars["token"]["attacker_balance"], 2 ** 256)

    def test_checked_arithmetic_reverts_instead(self):
        scenario = load_scenario_yaml(SCENARIO_PATH)
        executor = MockExecutor(contract_kinds={"token": "UncheckedBalanceToken"},
                                 contract_params={"token": {"checked": True}})
        result = executor.execute(scenario)
        self.assertTrue(result.reverted)
        self.assertIn("exceeds balance", result.revert_reason)


if __name__ == "__main__":
    unittest.main()
