import unittest

from shadow_strike.core.models import (
    AttackerModel,
    AttackScenario,
    InitialState,
    SuccessCondition,
    TransactionStep,
)
from shadow_strike.execution.mock_executor import (
    Ledger,
    MockExecutor,
    MockWorld,
    ReentrantAttacker,
    SafeVault,
    SimplePool,
)


class TestMockExecutor(unittest.TestCase):
    def scenario(self, steps, balances=None):
        return AttackScenario(
            vulnerability_class="accounting",
            target_protocol="Mock accounting",
            hypothesis="Check settlement and transaction boundaries",
            attacker=AttackerModel(initial_eth=10),
            initial_state=InitialState("unused", 0, {"target": "unused"}, balances or {}),
            steps=steps,
            success_conditions=[SuccessCondition("attacker.eth_balance_after >= 0", "Balance is present")],
        )

    def test_deposit_and_donation_settle_without_minting_donation_shares(self):
        executor = MockExecutor({"vault": "ERC4626LikeVault"})
        result = executor.execute(self.scenario([
            TransactionStep(1, "attacker", "vault", "deposit()", value_eth=2),
            TransactionStep(2, "attacker", "vault", "donate()", value_eth=3),
        ]))
        self.assertFalse(result.reverted)
        self.assertEqual(result.state_diff["after"], {"attacker": 5, "vault": 5})
        self.assertEqual(result.state_vars["vault"]["total_assets"], 5)
        self.assertEqual(result.state_vars["vault"]["total_shares"], 2)

    def test_swap_settles_both_assets(self):
        pool = SimplePool("pool", reserve_a=10, reserve_b=20)
        world = MockWorld(Ledger({"pool": 10, "trader": 12}), {"pool": pool},
                          token_b_ledger=Ledger({"pool": 20}))
        self.assertEqual(pool.swapAForB("trader", world, amount_a=10), 10)
        self.assertEqual(world.ledger.balances, {"pool": 20, "trader": 2})
        self.assertEqual(world.token_b_ledger.balances, {"pool": 10, "trader": 10})
        self.assertEqual((pool.reserve_a, pool.reserve_b), (20, 10))

    def test_open_position_pays_debt_from_market(self):
        executor = MockExecutor({"market": "SelfLiquidationMarket"})
        result = executor.execute(self.scenario([
            TransactionStep(1, "attacker", "market", "openPosition(uint256,uint256)", [6, 4]),
        ], {"market": 10}))
        self.assertFalse(result.reverted)
        self.assertEqual(result.state_diff["after"], {"attacker": 8, "market": 12})

    def test_expected_revert_allows_later_step(self):
        executor = MockExecutor({"vault": "SafeVault"})
        result = executor.execute(self.scenario([
            TransactionStep(1, "attacker", "vault", "withdraw()", expected_revert=True),
            TransactionStep(2, "attacker", "vault", "deposit()", value_eth=2),
        ]))
        self.assertFalse(result.reverted)
        self.assertIsNone(result.revert_reason)
        self.assertEqual(result.state_diff["after"], {"vault": 2, "attacker": 8})
        self.assertEqual([entry["fn"] for entry in result.call_trace], ["deposit"])

    def test_revert_restores_pre_step_state_and_trace(self):
        executor = MockExecutor(
            {"vault": "ERC4626LikeVault", "attacker": "ShareInflationAttacker"},
            {"attacker": {"vault_alias": "vault"}},
        )
        deposit = TransactionStep(1, "attacker", "vault", "deposit()", value_eth=2)
        baseline = executor.execute(self.scenario([deposit]))
        failing_step = TransactionStep(2, "attacker", "attacker", "attack(uint256)", [20])
        later_step = TransactionStep(3, "attacker", "vault", "deposit()", value_eth=1)
        result = executor.execute(self.scenario([deposit, failing_step, later_step]))
        self.assertTrue(result.reverted)
        self.assertIn("insufficient balance", result.revert_reason)
        self.assertEqual(result.state_vars, baseline.state_vars)
        self.assertEqual(result.call_trace, baseline.call_trace)

    def test_receive_skips_reentry_without_a_remaining_deposit(self):
        vault = SafeVault("vault")
        attacker = ReentrantAttacker("attacker", "vault")
        world = MockWorld(Ledger({"attacker": 2, "vault": 10}), {"vault": vault, "attacker": attacker})
        vault.deposit("attacker", world, 2)
        vault.withdraw("attacker", world)
        self.assertEqual(attacker.reentry_count, 0)
