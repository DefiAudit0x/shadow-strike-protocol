"""Live proof of flash_loan's documented design: it composes with
another vulnerability class (reentrancy here) rather than standing
alone — see attack_library/flash_loan/meta.yaml's `composes_with`.
The attacker needs ZERO starting capital."""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import Mock

from shadow_strike.agent.graph_simple import SimpleShadowStrikeGraph
from shadow_strike.attack_library.registry import AttackLibrary
from shadow_strike.core.scenario_loader import load_scenario_yaml
from shadow_strike.execution.mock_executor import MockExecutor
from shadow_strike.verifier.verifier import Verifier

SCENARIO_PATH = Path(__file__).parent.parent / "examples" / "scenarios" / "flash_loan_reentrancy_demo.yaml"


class TestFlashLoanComposition(unittest.TestCase):
    def _executor(self, fee_bps=9):
        return MockExecutor(
            contract_kinds={"vault": "VulnerableVault", "lender": "MockFlashLender", "attacker": "FlashLoanReentrantAttacker"},
            contract_params={
                "lender": {"fee_bps": fee_bps},
                "attacker": {"lender_alias": "lender", "vault_alias": "vault"},
            },
        )

    def test_zero_capital_attacker_profits(self):
        scenario = load_scenario_yaml(SCENARIO_PATH)
        self.assertEqual(scenario.attacker.initial_eth, 0.0)  # confirms the "zero capital" premise is in the scenario itself

        result = self._executor().execute(scenario)
        verdict = Verifier().verify(scenario, result)

        self.assertFalse(result.reverted, result.revert_reason)
        self.assertTrue(verdict.verified)
        self.assertGreater(result.state_vars["attacker"]["eth_balance_after"], 0)

    def test_insufficient_lender_liquidity_reverts_cleanly(self):
        scenario = load_scenario_yaml(SCENARIO_PATH)
        scenario.initial_state.balances["lender"] = 1.0   # less than the 5.0 ETH borrow requested
        result = self._executor().execute(scenario)
        self.assertTrue(result.reverted)
        self.assertIn("insufficient liquidity", result.revert_reason)

    def test_fee_is_actually_deducted_from_profit(self):
        scenario = load_scenario_yaml(SCENARIO_PATH)
        low_fee_result = self._executor(fee_bps=9).execute(scenario)
        high_fee_result = self._executor(fee_bps=500).execute(scenario)  # 5% — unrealistic but proves the mechanism
        low_profit = low_fee_result.state_vars["attacker"]["eth_balance_after"]
        high_profit = high_fee_result.state_vars["attacker"]["eth_balance_after"]
        self.assertGreater(low_profit, high_profit)  # higher fee must mean lower attacker profit

    def test_flash_loan_hypothesis_ends_with_unsupported_verdict(self):
        source = """
        contract FlashLoanTarget {
            function flashLoan(uint256 amount) external {}
        }
        """
        executor = Mock()
        graph = SimpleShadowStrikeGraph(
            executor=executor, verifier=Verifier(), library=AttackLibrary(), max_retries=1,
        )

        result = graph.run(
            target_contract_source=source,
            target_protocol_name="FlashLoanTarget",
            fork_url="", fork_block=0,
            target_contracts={"target": "0xabc"},
            attacker_initial_eth=1.0,
        )

        self.assertIn("flash_loan", [h["vulnerability_class"] for h in result["hypotheses"]])
        self.assertEqual(result["verdict"], "unsupported_class")
        self.assertEqual(result["stopped_reason"], "unsupported_class")
        self.assertIsNone(result["current_scenario"])
        self.assertNotIn("planner_error", result)
        executor.execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
