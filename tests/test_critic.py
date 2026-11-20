"""Part 9 tests — the critic's adjustments actually change the next attempt.

The critic used to write its "increase_max_reentries" adjustment to a state
key nothing ever read, AttackScenario.max_retries never bounded the graph
loop, and the critic never looked at the history it wrote. These tests prove
each of the three is now real.
"""
from __future__ import annotations

import unittest

from shadow_strike.agent.graph_simple import SimpleShadowStrikeGraph
from shadow_strike.agent.nodes import critic_node
from shadow_strike.attack_library.registry import AttackLibrary
from shadow_strike.execution.mock_executor import MockExecutor
from shadow_strike.verifier.verifier import Verifier

_SOURCE = """
contract Vault {
    function withdraw() external {
        (bool ok,) = msg.sender.call{value: 1}("");
    }
}
"""


def _run_resisting_graph(graph_max_retries=3, on_step=None):
    """Run the graph against a SafeVault, which resists every attempt, so
    the retry loop (not a verification) is what stops the run."""
    executor = MockExecutor(contract_kinds={"vault": "SafeVault", "attacker": "ReentrantAttacker"})
    graph = SimpleShadowStrikeGraph(
        executor=executor, verifier=Verifier(), library=AttackLibrary(),
        max_retries=graph_max_retries,
    )
    return graph.run(
        target_contract_source=_SOURCE,
        target_protocol_name="InlineTestVault",
        fork_url="", fork_block=0,
        target_contracts={"vault": "0xdead"},
        attacker_initial_eth=1.0,
        on_step=on_step,
    )


class TestCriticRetry(unittest.TestCase):
    def test_retry_increases_attacker_max_reentries(self):
        planner_depths = []

        def capture(label, state):
            if label == "scenario_planner" and state.get("current_scenario") is not None:
                planner_depths.append(state["current_scenario"].attacker_max_reentries)

        result = _run_resisting_graph(graph_max_retries=3, on_step=capture)
        # First attempt runs with the default depth (3); the critic's
        # increase_max_reentries adjustment must reach the second attempt.
        self.assertEqual(planner_depths[0], 3)
        self.assertEqual(planner_depths[1], 5)
        self.assertEqual(result["attempt_count"], 3)

    def test_executor_uses_scenario_max_reentries(self):
        # Direct proof the scenario field reaches the constructed attacker:
        # a deeper limit produces a deeper reentrant call trace on the
        # vulnerable vault.
        import sys
        sys.path.insert(0, "tests")
        from test_pipeline import _make_scenario

        executor = MockExecutor(contract_kinds={"vault": "VulnerableVault", "attacker": "ReentrantAttacker"})
        shallow = executor.execute(_make_scenario(attacker_max_reentries=3))
        deep = executor.execute(_make_scenario(attacker_max_reentries=5))
        self.assertGreater(len(deep.call_trace), len(shallow.call_trace))
        self.assertGreater(
            deep.state_vars["attacker"]["eth_balance_after"],
            shallow.state_vars["attacker"]["eth_balance_after"],
        )

    def test_scenario_max_retries_bounds_graph_loop(self):
        # The graph's own cap is loose (10); the scenario's default
        # max_retries is 3. The loop must stop at 3, proving the scenario
        # field — not just the graph constructor — bounds the loop.
        result = _run_resisting_graph(graph_max_retries=10)
        self.assertEqual(result["attempt_count"], 3)
        self.assertEqual(result["stopped_reason"], "max_retries (3) exhausted without verification")

    def test_critic_does_not_repeat_failed_adjustment(self):
        import sys
        sys.path.insert(0, "tests")
        from test_pipeline import _make_scenario

        scenario = _make_scenario()
        executor = MockExecutor(contract_kinds={"vault": "SafeVault", "attacker": "ReentrantAttacker"})
        execution = executor.execute(scenario)
        verdict = Verifier().verify(scenario, execution)
        self.assertFalse(verdict.verified)

        state = {
            "current_scenario": scenario,
            "execution_result": execution,
            "verifier_verdict": verdict,
            "attempt_count": 0,
            "history": [],
        }
        first = critic_node(state)
        self.assertEqual(first["_critic_adjustment"], "increase_max_reentries")

        # Same failure again: the critic reads its history and must not
        # propose the adjustment that already failed.
        second = critic_node(state)
        self.assertIsNone(second["_critic_adjustment"])
        self.assertEqual(second["history"][-1]["adjustment_applied"], None)


if __name__ == "__main__":
    unittest.main()
