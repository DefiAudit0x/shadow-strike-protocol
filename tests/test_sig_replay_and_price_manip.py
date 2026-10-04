"""Live proof of signature_replay and price_manipulation — both the
exploitable and the fixed/resistant case for each."""
from __future__ import annotations

import unittest

from shadow_strike.core.models import AttackScenario, AttackerModel, InitialState, TransactionStep, SuccessCondition
from shadow_strike.execution.mock_executor import MockExecutor
from shadow_strike.verifier.verifier import Verifier


class TestSignatureReplayLive(unittest.TestCase):
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
    def _scenario(self):
        return AttackScenario(
            vulnerability_class="price_manipulation", target_protocol="VaultTest",
            hypothesis="first-depositor donation/inflation attack",
            attacker=AttackerModel(initial_eth=10.0),
            initial_state=InitialState(fork_url="x", fork_block=1, target_contracts={"vault": "0xdef"}),
            steps=[
                TransactionStep(step_id=1, caller="attacker", target="attacker", function="attack()", value_eth=9.99, args=[9.99]),
                TransactionStep(step_id=2, caller="victim", target="vault", function="deposit()", value_eth=1.0),
            ],
            success_conditions=[SuccessCondition(expression="vault.victim_shares < 0.01", description="victim got ~nothing")],
        )

    def test_vulnerable_vault_rounds_victim_to_zero(self):
        s = self._scenario()
        executor = MockExecutor(
            contract_kinds={"vault": "ERC4626LikeVault", "attacker": "ShareInflationAttacker"},
            contract_params={"vault": {"donation_resistant": False}, "attacker": {"vault_alias": "vault"}},
        )
        verdict = Verifier().verify(s, executor.execute(s))
        self.assertTrue(verdict.verified)

    def test_donation_resistant_vault_protects_victim(self):
        s = self._scenario()
        executor = MockExecutor(
            contract_kinds={"vault": "ERC4626LikeVault", "attacker": "ShareInflationAttacker"},
            contract_params={"vault": {"donation_resistant": True}, "attacker": {"vault_alias": "vault"}},
        )
        result = executor.execute(s)
        verdict = Verifier().verify(s, result)
        self.assertFalse(verdict.verified)
        self.assertGreater(result.state_vars["vault"]["victim_shares"], 1000)  # victim got real shares


if __name__ == "__main__":
    unittest.main()
