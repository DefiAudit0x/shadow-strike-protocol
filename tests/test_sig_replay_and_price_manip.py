"""Live proof of signature_replay and price_manipulation — both the
exploitable and the fixed/resistant case for each."""
from __future__ import annotations

import unittest

from shadow_strike.agent.nodes import _build_price_manipulation_scenario, _build_signature_replay_scenario
from shadow_strike.core.models import (
    AttackerModel,
    AttackScenario,
    InitialState,
    SuccessCondition,
    TransactionStep,
)
from shadow_strike.execution.mock_executor import ERC4626LikeVault, Ledger, MockExecutor, MockWorld
from shadow_strike.verifier.verifier import Verifier


class TestSignatureReplayLive(unittest.TestCase):
    def test_planner_declares_string_argument_in_both_abi_signatures(self):
        scenario = _build_signature_replay_scenario(
            {"hypothesis": "a signature can be replayed"}, {"target": "0xabc"},
            0.0, "x", 1, None, "SigTest", {},
        )
        self.assertEqual([step.function for step in scenario.steps], [
            "executeSignedAction(string)", "executeSignedAction(string)",
        ])
        for step in scenario.steps:
            self.assertEqual(len(step.args), 1)
            self.assertEqual(step.function, f"executeSignedAction({','.join(['string'] * len(step.args))})")

    def _scenario(self):
        return AttackScenario(
            vulnerability_class="signature_replay", target_protocol="SigTest",
            hypothesis="no nonce/used-signature tracking",
            attacker=AttackerModel(initial_eth=0.0),
            initial_state=InitialState(fork_url="x", fork_block=1, target_contracts={"target": "0xabc"}),
            steps=[
                TransactionStep(step_id=1, caller="attacker", target="target", function="executeSignedAction()", args=["sig-1"]),
                TransactionStep(step_id=2, caller="attacker", target="target", function="executeSignedAction()", args=["sig-1"]),
            ],
            success_conditions=[SuccessCondition(expression="target.replay_count > 1", description="replayed")],
        )

    def test_no_tracking_is_exploitable(self):
        s = self._scenario()
        executor = MockExecutor(contract_kinds={"target": "SignedActionTarget"}, contract_params={"target": {"track_used": False}})
        verdict = Verifier().verify(s, executor.execute(s))
        self.assertTrue(verdict.verified)

    def test_used_signature_tracking_blocks_replay(self):
        s = self._scenario()
        executor = MockExecutor(contract_kinds={"target": "SignedActionTarget"}, contract_params={"target": {"track_used": True}})
        result = executor.execute(s)
        self.assertTrue(result.reverted)
        self.assertIn("already used", result.revert_reason)


class TestPriceManipulationLive(unittest.TestCase):
    def _scenario(self, initial_eth=10.0):
        return _build_price_manipulation_scenario(
            {"hypothesis": "first-depositor donation/inflation attack"},
            {"vault": "0xdef"}, initial_eth, "x", 1, None, "VaultTest", {},
        )

    def test_vulnerable_vault_rounds_victim_to_zero(self):
        s = self._scenario()
        executor = MockExecutor(
            contract_kinds={"vault": "ERC4626LikeVault", "attacker": "ShareInflationAttacker"},
            contract_params={"vault": {"donation_resistant": False}, "attacker": {"vault_alias": "vault"}},
        )
        result = executor.execute(s)
        self.assertFalse(result.reverted)
        self.assertIs(type(result.state_vars["vault"]["victim_shares"]), int)
        self.assertEqual(result.state_vars["vault"]["victim_shares"], 0)
        self.assertEqual(result.state_vars["vault"]["victim_claim_eth"], 0)
        self.assertTrue(Verifier().verify(s, result).verified)

    def test_partial_rounding_loss_is_measured_by_redeemable_claim(self):
        scenario = self._scenario(initial_eth=1.0)
        executor = MockExecutor(
            contract_kinds={"vault": "ERC4626LikeVault", "attacker": "ShareInflationAttacker"},
            contract_params={"attacker": {"vault_alias": "vault"}},
        )
        result = executor.execute(scenario)
        vault = result.state_vars["vault"]
        self.assertFalse(result.reverted)
        self.assertEqual(vault["victim_shares"], 1)
        self.assertEqual(vault["victim_claim_eth"], 0.995)
        self.assertTrue(Verifier().verify(scenario, result).verified)

    def test_resistant_first_deposit_uses_the_virtual_ratio(self):
        vault = ERC4626LikeVault("vault", donation_resistant=True)
        world = MockWorld(Ledger({"first": 1e-9, "second": 1e-9}))
        vault.deposit("first", world, msg_value=1e-9)
        vault.deposit("second", world, msg_value=1e-9)
        self.assertEqual(vault.shares_of, {"first": 1_000_000_000, "second": 1_000_000_000})

    def test_tiny_funds_price_manipulation_does_not_fail_for_insufficient_balance(self):
        """Fix 8b (CodeRabbit on PR #30): the fixed 1e-9 seed deposit inside
        ShareInflationAttacker.attack() was not capped by the declared funds,
        so a zero-capital (or sub-1e-9) price-manipulation scenario reverted
        for insufficient balance instead of executing and reading resisted."""
        for funds in (0.0, 1e-10):
            with self.subTest(funds=funds):
                scenario = self._scenario(initial_eth=funds)
                executor = MockExecutor(
                    contract_kinds={"vault": "ERC4626LikeVault", "attacker": "ShareInflationAttacker"},
                    contract_params={"attacker": {"vault_alias": "vault"}},
                )
                result = executor.execute(scenario)
                self.assertFalse(result.reverted, result.revert_reason)
                verdict = Verifier().verify(scenario, result)
                self.assertFalse(verdict.verified)
                self.assertEqual(verdict.verdict, "resisted")

    def test_donation_resistant_vault_protects_victim(self):
        s = self._scenario()
        executor = MockExecutor(
            contract_kinds={"vault": "ERC4626LikeVault", "attacker": "ShareInflationAttacker"},
            contract_params={"vault": {"donation_resistant": True}, "attacker": {"vault_alias": "vault"}},
        )
        result = executor.execute(s)
        verdict = Verifier().verify(s, result)
        self.assertFalse(verdict.verified)
        self.assertFalse(result.reverted, result.revert_reason)
        self.assertTrue(result.state_vars)
        self.assertEqual(verdict.verdict, "resisted")
        self.assertTrue(verdict.condition_results)
        self.assertTrue(all(c["error"] is None for c in verdict.condition_results))
        self.assertAlmostEqual(result.state_vars["vault"]["victim_claim_eth"], 1.0, places=8)


if __name__ == "__main__":
    unittest.main()
