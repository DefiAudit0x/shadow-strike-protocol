"""Live proof of the `accounting` class's hand-authoring path: a
concrete unchecked-arithmetic underflow bug, written by hand (no
automated builder exists for this class by design), run through the
same pipeline as every other scenario."""
from __future__ import annotations

import unittest
from pathlib import Path

from shadow_strike.core.scenario_loader import load_scenario_yaml
from shadow_strike.execution.mock_executor import (
    Ledger,
    MockExecutor,
    MockRevert,
    MockWorld,
    UncheckedBalanceToken,
)
from shadow_strike.verifier.verifier import Verifier

SCENARIO_PATH = Path(__file__).parent.parent / "examples" / "scenarios" / "accounting_underflow_demo.yaml"


class TestAccountingUnderflow(unittest.TestCase):
    def test_unchecked_self_transfer_wraps_receiver_addition(self):
        scenario = load_scenario_yaml(SCENARIO_PATH)
        executor = MockExecutor(contract_kinds={"token": "UncheckedBalanceToken"},
                                 contract_params={"token": {"checked": False}})
        result = executor.execute(scenario)
        verdict = Verifier().verify(scenario, result)

        self.assertFalse(result.reverted)
        self.assertFalse(verdict.verified)
        self.assertEqual(result.state_vars["token"]["attacker_balance"], 0)

    def test_token_rejects_amounts_outside_uint256(self):
        token = UncheckedBalanceToken("token")
        world = MockWorld(Ledger())
        for operation in (token.mint, token.transfer):
            for amount in (-1, 2 ** 256):
                with (
                    self.subTest(operation=operation.__name__, amount=amount),
                    self.assertRaisesRegex(MockRevert, "uint256"),
                ):
                    operation("sender", world, to="receiver", amount=amount)
        self.assertEqual(token.balances, {})

    def test_unchecked_underflow_to_another_receiver_stays_within_uint256(self):
        token = UncheckedBalanceToken("token")
        world = MockWorld(Ledger())
        token.mint("sender", world, to="receiver", amount=2 ** 256 - 1)
        token.transfer("sender", world, to="receiver", amount=1000)
        self.assertEqual(token.balances["sender"], 2 ** 256 - 1000)
        self.assertEqual(token.balances["receiver"], 999)

    def test_checked_arithmetic_reverts_instead(self):
        scenario = load_scenario_yaml(SCENARIO_PATH)
        executor = MockExecutor(contract_kinds={"token": "UncheckedBalanceToken"},
                                 contract_params={"token": {"checked": True}})
        result = executor.execute(scenario)
        self.assertTrue(result.reverted)
        self.assertIn("exceeds balance", result.revert_reason)


if __name__ == "__main__":
    unittest.main()
