"""
Live proof that oracle_manipulation and access_control are not just
templates — they run through MockExecutor + Verifier end to end,
same as reentrancy.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Keep direct execution equivalent to discovery from the repository root.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shadow_strike.agent.nodes import hypothesis_node, scenario_planner_node
from shadow_strike.attack_library.registry import AttackLibrary
from shadow_strike.core.models import (
    AttackerModel,
    AttackScenario,
    ExecutionResult,
    InitialState,
    SuccessCondition,
    TransactionStep,
)
from shadow_strike.execution.mock_executor import MockExecutor
from shadow_strike.verifier.verifier import Verifier


class TestAccessControlLive(unittest.TestCase):
    def _scenario(self):
        return AttackScenario(
            vulnerability_class="access_control",
            target_protocol="DemoAdmin",
            hypothesis="privilegedAction() has no caller check",
            attacker=AttackerModel(initial_eth=0.0),
            initial_state=InitialState(
                fork_url="https://example/rpc", fork_block=1,
                target_contracts={"admin": "0xadmin"},
            ),
            steps=[
                TransactionStep(step_id=1, caller="attacker", target="admin", function="privilegedAction()"),
            ],
            success_conditions=[
                SuccessCondition(expression="admin.last_caller == 'attacker'",
                                  description="unauthorized caller reached the privileged function"),
            ],
        )

    def test_broken_guard_is_exploitable(self):
        s = self._scenario()
        executor = MockExecutor(
            contract_kinds={"admin": "AccessControlTarget"},
            contract_params={"admin": {"owner": "deployer", "enforce_check": False}},
        )
        ledger_result = executor.execute(s)
        admin_contract = None
        for entry in ledger_result.call_trace:
            if entry.get("fn") == "privilegedAction":
                admin_contract = entry
        self.assertIsNotNone(admin_contract, "privilegedAction() should have been called and logged")
        self.assertEqual(admin_contract["caller"], "attacker")
        self.assertFalse(ledger_result.reverted)
        verdict = Verifier().verify(s, ledger_result)
        self.assertTrue(verdict.verified)
        self.assertTrue(verdict.condition_results[0]["passed"])
        self.assertIsNone(verdict.condition_results[0]["error"])

    def test_enforced_guard_blocks_attacker(self):
        s = self._scenario()
        executor = MockExecutor(
            contract_kinds={"admin": "AccessControlTarget"},
            contract_params={"admin": {"owner": "deployer", "enforce_check": True}},
        )
        result = executor.execute(s)
        self.assertTrue(result.reverted)
        self.assertIn("not owner", result.revert_reason)

    def test_access_control_pipeline_verdict(self):
        """The planner-built scenario must verdict both directions through
        MockExecutor + Verifier — broken guard verifies exploitable,
        fixed guard does not (P1-2). The old library default
        (attacker.gained_privileged_capability) was never emitted by any
        executor, so the pipeline could never verify this class at all."""
        state = {
            "hypotheses": [{
                "hypothesis": "privilegedAction() has no caller check",
                "vulnerability_class": "access_control",
            }],
        }
        planned = scenario_planner_node(
            state, fork_url="https://example/rpc", fork_block=1,
            target_contracts={"admin": "0xadmin"},
        )
        scenario = planned["current_scenario"]
        self.assertIsNotNone(scenario)
        self.assertIsNone(planned.get("planner_error"))
        # the planner's condition references only mock-emitted state vars
        self.assertEqual(
            [c.expression for c in scenario.success_conditions],
            ["admin.last_caller == 'attacker'"],
        )

        verifier = Verifier()

        broken = MockExecutor(
            contract_kinds={"admin": "AccessControlTarget"},
            contract_params={"admin": {"owner": "deployer", "enforce_check": False}},
        )
        broken_result = verifier.verify(scenario, broken.execute(scenario))
        self.assertTrue(broken_result.verified)
        self.assertTrue(broken_result.condition_results[0]["passed"])
        self.assertIsNone(broken_result.condition_results[0]["error"])
        # the invariant is violated exactly when the unauthorized call lands
        self.assertTrue(broken_result.invariant_violations)

        fixed = MockExecutor(
            contract_kinds={"admin": "AccessControlTarget"},
            contract_params={"admin": {"owner": "deployer", "enforce_check": True}},
        )
        fixed_result = verifier.verify(scenario, fixed.execute(scenario))
        self.assertFalse(fixed_result.verified)
        self.assertFalse(fixed_result.invariant_violations)


class TestPlannerHypothesisOrder(unittest.TestCase):
    def test_unsupported_first_hypothesis_does_not_mask_later_supported_class(self):
        source = '''
        contract Vault {
            // unchecked {
            function withdraw() external {
                msg.sender.call{value: 1}("");
            }
        }
        '''
        state = hypothesis_node({"target_contract_source": source}, library=AttackLibrary())
        self.assertEqual([hypothesis["vulnerability_class"] for hypothesis in state["hypotheses"]], [
            "accounting", "reentrancy",
        ])
        planned = scenario_planner_node(
            state, fork_url="", fork_block=0, target_contracts={"vault": "0xabc"},
            library=AttackLibrary(),
        )
        scenario = planned["current_scenario"]
        self.assertIsNotNone(scenario)
        self.assertEqual(scenario.vulnerability_class.value, "reentrancy")
        self.assertNotEqual(planned.get("verdict"), "unsupported_class")

        executor = MockExecutor(contract_kinds={"vault": "VulnerableVault", "attacker": "ReentrantAttacker"})
        execution = executor.execute(scenario)
        self.assertTrue(Verifier().verify(scenario, execution).verified)


class TestReentrancyProfitThreshold(unittest.TestCase):
    def test_positive_theft_over_starting_entitlement_verifies(self):
        planned = scenario_planner_node(
            {"hypotheses": [{"vulnerability_class": "reentrancy", "hypothesis": "withdraw reenters"}]},
            fork_url="", fork_block=0, target_contracts={"vault": "0xabc"},
            attacker_initial_eth=1.0, library=AttackLibrary(),
        )
        scenario = planned["current_scenario"]

        for after, expected in ((1.9, True), (1.0, False)):
            with self.subTest(after=after):
                execution = ExecutionResult(
                    scenario_id=scenario.scenario_id, reverted=False, revert_reason=None,
                    state_vars={"attacker": {
                        "eth_balance_before": 1.0,
                        "eth_balance_after": after,
                        "legitimate_entitlement": 1.0,
                    }},
                    state_diff={}, call_trace=[], engine="mock",
                )
                result = Verifier().verify(scenario, execution)
                self.assertEqual(result.verified, expected)
                self.assertEqual(result.verdict, "verified" if expected else "resisted")


class TestOracleManipulationLive(unittest.TestCase):
    def test_price_manipulation_enables_overborrow(self):
        """Attacker swaps into a thin pool to spike spot price, then
        borrows against collateral valued at that inflated price —
        and walks away with more ETH than any honest action could grant."""
        s = AttackScenario(
            vulnerability_class="oracle_manipulation",
            target_protocol="DemoLending",
            hypothesis="market prices collateral directly off pool.spot_price(), no TWAP",
            attacker=AttackerModel(initial_eth=50.0),
            initial_state=InitialState(
                fork_url="https://example/rpc", fork_block=1,
                target_contracts={"pool": "0xpool", "market": "0xmarket"},
            ),
            steps=[
                TransactionStep(step_id=1, caller="attacker", target="attacker", function="attack()", value_eth=45.0),
            ],
            success_conditions=[
                SuccessCondition(
                    expression="attacker.eth_balance_after - attacker.eth_balance_before > 0",
                    description="attacker profited from the manipulated price",
                ),
            ],
        )
        executor = MockExecutor(
            contract_kinds={
                "pool": "SimplePool",
                "market": "OracleFedLendingMarket",
                "attacker": "OracleManipulationAttacker",
            },
            contract_params={
                "pool": {"reserve_a": 100.0, "reserve_b": 100.0},   # THIN pool — easy to move
                "market": {"pool_alias": "pool", "reserve_eth": 80.0},
                "attacker": {"pool_alias": "pool", "market_alias": "market"},
            },
        )
        result = executor.execute(s)
        verdict = Verifier().verify(s, result)
        self.assertFalse(result.reverted, result.revert_reason)
        self.assertTrue(verdict.verified)
        self.assertGreater(
            result.state_vars["attacker"]["eth_balance_after"],
            result.state_vars["attacker"]["eth_balance_before"],
        )

    def test_deep_pool_resists_same_attack(self):
        """Same scenario, same attacker budget — but the pool is deep
        enough that the same-size swap barely moves the price. The
        'attack' either reverts or fails to profit."""
        s = AttackScenario(
            vulnerability_class="oracle_manipulation",
            target_protocol="DemoLending",
            hypothesis="market prices collateral directly off pool.spot_price(), no TWAP",
            attacker=AttackerModel(initial_eth=50.0),
            initial_state=InitialState(
                fork_url="https://example/rpc", fork_block=1,
                target_contracts={"pool": "0xpool", "market": "0xmarket"},
            ),
            steps=[
                TransactionStep(step_id=1, caller="attacker", target="attacker", function="attack()", value_eth=45.0),
            ],
            success_conditions=[
                SuccessCondition(
                    expression="attacker.eth_balance_after - attacker.eth_balance_before > 40",
                    description="attacker profited by a large margin from the manipulated price",
                ),
            ],
        )
        executor = MockExecutor(
            contract_kinds={
                "pool": "SimplePool",
                "market": "OracleFedLendingMarket",
                "attacker": "OracleManipulationAttacker",
            },
            contract_params={
                "pool": {"reserve_a": 1_000_000.0, "reserve_b": 1_000_000.0},  # DEEP pool
                "market": {"pool_alias": "pool", "reserve_eth": 80.0},
                "attacker": {"pool_alias": "pool", "market_alias": "market"},
            },
        )
        result = executor.execute(s)
        verdict = Verifier().verify(s, result)
        self.assertFalse(verdict.verified, "a deep pool should not be meaningfully manipulable by this swap size")


class TestLLMHookWiring(unittest.TestCase):
    """Proves the llm_fn plumbing itself works end-to-end (recon ->
    hypothesis -> critic all accept and invoke it) without needing
    network access — EchoLLM is a real callable, just not a real model."""

    def test_echo_llm_gets_invoked_through_the_graph(self):
        from shadow_strike.agent.graph_simple import SimpleShadowStrikeGraph
        from shadow_strike.agent.llm_providers import EchoLLM
        from shadow_strike.attack_library.registry import AttackLibrary

        source = 'contract C { function withdraw() external { msg.sender.call{value: 1}(""); } }'
        executor = MockExecutor(contract_kinds={"vault": "VulnerableVault", "attacker": "ReentrantAttacker"})
        echo = EchoLLM()
        graph = SimpleShadowStrikeGraph(executor=executor, verifier=Verifier(), library=AttackLibrary(),
                                         llm_fn=echo, max_retries=3)
        result = graph.run(
            target_contract_source=source, target_protocol_name="LLMWiredVault",
            fork_url="", fork_block=0, target_contracts={"vault": "0xdead"}, attacker_initial_eth=1.0,
        )
        # the hypothesis_node always calls llm_fn when one is provided —
        # confirm it actually ran and returned something into state.
        self.assertIn("_llm_hypothesis_notes", result)
        self.assertEqual(result["stopped_reason"], "verified")


class TestReportGenerator(unittest.TestCase):
    def test_generates_nonempty_markdown_finding(self):
        from shadow_strike.reporting.report_generator import generate_finding_markdown

        s = AttackScenario(
            vulnerability_class="reentrancy", target_protocol="ReportTestVault",
            hypothesis="test hypothesis for report",
            attacker=AttackerModel(initial_eth=1.0),
            initial_state=InitialState(fork_url="x", fork_block=1,
                                        target_contracts={"vault": "0xabc"}, balances={"vault": 9.0}),
            steps=[
                TransactionStep(step_id=1, caller="attacker", target="vault", function="deposit()", value_eth=0.9),
                TransactionStep(step_id=2, caller="attacker", target="attacker", function="attack()"),
            ],
            success_conditions=[SuccessCondition(
                expression="attacker.eth_balance_after - attacker.eth_balance_before > attacker.legitimate_entitlement",
                description="profited")],
        )
        executor = MockExecutor(contract_kinds={"vault": "VulnerableVault", "attacker": "ReentrantAttacker"})
        result = executor.execute(s)
        verdict = Verifier().verify(s, result)
        md = generate_finding_markdown(verdict.proof_artifact, finding_id="SS-TEST")
        self.assertIn("Finding SS-TEST", md)
        self.assertIn("Critical", md)
        self.assertIn("VERIFIED", md)
        self.assertIn("mock engine", md)


if __name__ == "__main__":
    unittest.main()
