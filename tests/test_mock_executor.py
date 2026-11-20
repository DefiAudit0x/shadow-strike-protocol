import unittest

from shadow_strike.core.models import (
    AttackerModel,
    AttackScenario,
    InitialState,
    ShadowStrikeValidationError,
    SuccessCondition,
    TransactionStep,
)
from shadow_strike.execution.mock_executor import (
    Ledger,
    MockExecutor,
    MockRevert,
    MockWorld,
    OracleFedLendingMarket,
    ReentrantAttacker,
    SafeVault,
    SelfLiquidationMarket,
    SimplePool,
    VulnerableVault,
)
from shadow_strike.verifier.verifier import Verifier


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

    def test_negative_transfer_raises_and_zero_transfer_is_a_noop(self):
        ledger = Ledger({"sender": 2})
        world = MockWorld(ledger)
        with self.assertRaises(ShadowStrikeValidationError):
            ledger.transfer("sender", "recipient", -1, world)
        ledger.transfer("sender", "recipient", 0, world)
        self.assertEqual(ledger.balances, {"sender": 2})

    def test_before_snapshot_uses_post_setup_balance(self):
        scenario = self.scenario([TransactionStep(1, "attacker", "vault", "deposit()", value_eth=1)])
        scenario.initial_state.custom_setup_calls = [
            TransactionStep(0, "attacker", "vault", "deposit()", value_eth=3),
        ]
        result = MockExecutor({"vault": "SafeVault"}).execute(scenario)
        self.assertEqual(result.state_diff["before"], {"vault": 3, "attacker": 7})
        self.assertEqual(result.state_diff["after"], {"vault": 4, "attacker": 6})

    def test_missing_expected_revert_prevents_verification(self):
        scenario = self.scenario([
            TransactionStep(1, "attacker", "vault", "deposit()", value_eth=2, expected_revert=True),
        ])
        result = MockExecutor({"vault": "SafeVault"}).execute(scenario)
        self.assertTrue(result.reverted)
        self.assertIn("expected revert", result.revert_reason)
        self.assertFalse(Verifier().verify(scenario, result).verified)

    def test_vault_call_rejects_wrong_abi_signature(self):
        scenario = self.scenario([TransactionStep(1, "attacker", "vault", "deposit(uint256)")])
        with self.assertRaises(ShadowStrikeValidationError):
            MockExecutor({"vault": "SafeVault"}).execute(scenario)

    def test_vault_call_rejects_extra_argument(self):
        scenario = self.scenario([TransactionStep(1, "attacker", "vault", "deposit()", [1])])
        with self.assertRaises(ShadowStrikeValidationError):
            MockExecutor({"vault": "SafeVault"}).execute(scenario)

    def test_caught_reentry_revert_rolls_back_partial_writes(self):
        # E08: SafeVault.withdraw writes deposits=0 BEFORE the transfer; if
        # the transfer reverts inside a re-entry, the caught revert must
        # roll the write back (EVM atomicity), while the outer transfer and
        # the caller's own reentry_count increment persist.
        vault1 = VulnerableVault("vault1")
        vault2 = SafeVault("vault2")
        attacker = ReentrantAttacker("attacker", "vault2", max_reentries=3)
        world = MockWorld(
            Ledger({"attacker": 5, "vault1": 10, "vault2": 1.5}),
            {"vault1": vault1, "vault2": vault2, "attacker": attacker},
        )
        vault1.deposits["attacker"] = 1.0
        vault2.deposits["attacker"] = 2.0
        vault1.withdraw("attacker", world)
        # the re-entry's deposits=0 write was rolled back ...
        self.assertEqual(world.contracts["vault2"].deposits["attacker"], 2.0)
        # ... the outer transfer was NOT rolled back ...
        self.assertEqual(world.ledger.get("vault1"), 9.0)
        self.assertEqual(world.ledger.get("attacker"), 6.0)
        # ... and the caller's own reentry_count increment persists.
        self.assertEqual(world.contracts["attacker"].reentry_count, 1)

    def test_reentrancy_target_comes_from_config(self):
        # E15: the reentrant target is the configured target_alias, not the
        # first non-attacker contract.
        steps = [TransactionStep(1, "attacker", "attacker", "attack()", value_eth=1)]
        kinds = {
            "vault1": "VulnerableVault",
            "vault2": "VulnerableVault",
            "attacker": "ReentrantAttacker",
        }
        result = MockExecutor(kinds, {"attacker": {"target_alias": "vault2"}}).execute(
            self.scenario(steps, {"vault1": 10, "vault2": 10})
        )
        self.assertEqual(result.state_vars["vault2"]["eth_balance_before"], 10)
        self.assertLess(result.state_vars["vault2"]["eth_balance_after"], 10)
        self.assertEqual(result.state_vars["vault1"]["eth_balance_after"], 10)
        # control: without the config the first non-attacker contract wins.
        control = MockExecutor(kinds).execute(self.scenario(steps, {"vault1": 10, "vault2": 10}))
        self.assertLess(control.state_vars["vault1"]["eth_balance_after"], 10)
        self.assertEqual(control.state_vars["vault2"]["eth_balance_after"], 10)

    def test_unknown_method_is_validation_error_not_revert(self):
        # E16 (remainder): a call to a method the mock does not implement is
        # a malformed scenario, never a revert — it must not satisfy
        # expected_revert either.
        scenario = self.scenario([TransactionStep(1, "attacker", "pool", "nonexistent()")])
        with self.assertRaises(ShadowStrikeValidationError):
            MockExecutor({"pool": "SimplePool"}).execute(scenario)
        scenario = self.scenario([
            TransactionStep(1, "attacker", "pool", "nonexistent()", expected_revert=True)
        ])
        with self.assertRaises(ShadowStrikeValidationError):
            MockExecutor({"pool": "SimplePool"}).execute(scenario)

    def test_deposit_and_donation_settle_without_minting_donation_shares(self):
        executor = MockExecutor({"vault": "ERC4626LikeVault"})
        result = executor.execute(self.scenario([
            TransactionStep(1, "attacker", "vault", "deposit()", value_eth=2),
            TransactionStep(2, "attacker", "vault", "donate()", value_eth=3),
        ]))
        self.assertFalse(result.reverted)
        self.assertEqual(result.state_diff["after"], {"attacker": 5, "vault": 5})
        self.assertEqual(result.state_vars["vault"]["total_assets"], 5)
        self.assertEqual(result.state_vars["vault"]["total_shares"], 2_000_000_000)

    def test_swap_settles_both_assets(self):
        pool = SimplePool("pool", reserve_a=10, reserve_b=20)
        world = MockWorld(Ledger({"pool": 10, "trader": 12}), {"pool": pool},
                          token_b_ledger=Ledger({"pool": 20}))
        self.assertEqual(pool.swapAForB("trader", world, amount_a=10), 10)
        self.assertEqual(world.ledger.balances, {"pool": 20, "trader": 2})
        self.assertEqual(world.token_b_ledger.balances, {"pool": 10, "trader": 10})
        self.assertEqual((pool.reserve_a, pool.reserve_b), (20, 10))

    def test_oracle_market_conserves_eth_and_accounts_for_debt(self):
        pool = SimplePool("pool", reserve_a=10, reserve_b=10)
        market = OracleFedLendingMarket("market", pool, reserve_eth=50)
        world = MockWorld(Ledger({"market": 50, "borrower": 1}))

        market.depositCollateral("borrower", world, msg_value=1)
        self.assertEqual(world.ledger.balances, {"market": 51, "borrower": 0})
        market.borrowAgainstCollateral("borrower", world)
        self.assertEqual(world.ledger.balances, {"market": 50, "borrower": 1})
        self.assertEqual(market.debt["borrower"], 1)
        with self.assertRaisesRegex(MockRevert, "nothing borrowable"):
            market.borrowAgainstCollateral("borrower", world)
        self.assertEqual(world.ledger.balances, {"market": 50, "borrower": 1})
        self.assertEqual(market.debt["borrower"], 1)

    def test_second_position_adds_to_existing_collateral_and_debt(self):
        market = SelfLiquidationMarket("market")
        world = MockWorld(Ledger({"market": 10, "borrower": 10}))
        market.openPosition("borrower", world, collateral_amt=6, debt_amt=4)
        market.openPosition("borrower", world, collateral_amt=3, debt_amt=2)
        self.assertEqual((market.collateral["borrower"], market.debt["borrower"]), (9, 6))
        self.assertEqual(world.ledger.balances, {"market": 13, "borrower": 7})

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
        self.assertEqual([entry["fn"] for entry in result.call_trace], ["withdraw()", "deposit"])
        self.assertEqual(result.call_trace[0]["outcome"], "expected_revert")

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
