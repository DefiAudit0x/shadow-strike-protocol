"""LangGraph finalization tests run without requiring the optional package."""
from __future__ import annotations

import importlib
import sys
import types
import unittest
from unittest.mock import patch

from shadow_strike.attack_library.registry import AttackLibrary
from shadow_strike.execution.mock_executor import MockExecutor
from shadow_strike.verifier.verifier import Verifier


class _FakeCompiledGraph:
    def __init__(self, graph):
        self.graph = graph

    def invoke(self, initial_state):
        state = dict(initial_state)
        node_name = self.graph.entry_point
        while node_name is not self.graph.end:
            output = self.graph.nodes[node_name](state)
            if output is not None:
                state.update(output)
            if node_name in self.graph.conditional_edges:
                router, destinations = self.graph.conditional_edges[node_name]
                node_name = destinations[router(state)]
            else:
                node_name = self.graph.edges[node_name]
        return state


class _FakeStateGraph:
    def __init__(self, state_type):
        self.nodes = {}
        self.edges = {}
        self.conditional_edges = {}
        self.end = _FakeLangGraphModule.END

    def add_node(self, name, function):
        self.nodes[name] = function

    def set_entry_point(self, name):
        self.entry_point = name

    def add_edge(self, source, destination):
        self.edges[source] = destination

    def add_conditional_edges(self, source, router, destinations):
        self.conditional_edges[source] = (router, destinations)

    def compile(self):
        return _FakeCompiledGraph(self)


_FakeLangGraphModule = types.ModuleType("langgraph.graph")
_FakeLangGraphModule.END = object()
_FakeLangGraphModule.StateGraph = _FakeStateGraph
_FakeLangGraphPackage = types.ModuleType("langgraph")


def _run_graph(*, source, executor, max_retries=1):
    module_name = "shadow_strike.agent.graph_langgraph"
    cached_module = sys.modules.pop(module_name, None)
    fake_graph_module = _FakeLangGraphModule
    try:
        with patch.dict(sys.modules, {
            "langgraph": _FakeLangGraphPackage,
            "langgraph.graph": fake_graph_module,
        }):
            graph_module = importlib.import_module(module_name)
            graph = graph_module.build_graph(
                executor=executor, verifier=Verifier(), library=AttackLibrary(),
                max_retries=max_retries, target_contracts={"vault": "0xabc"},
            )
            return graph.invoke({
                "target_contract_source": source,
                "target_protocol_name": "GraphTestVault",
                "attempt_count": 0,
                "history": [],
            })
    finally:
        sys.modules.pop(module_name, None)
        if cached_module is not None:
            sys.modules[module_name] = cached_module


class TestLangGraphFinalization(unittest.TestCase):
    SOURCE = """
    contract Vault {
        function withdraw() external {
            (bool ok,) = msg.sender.call{value: 1}("");
        }
    }
    """

    def test_success_sets_proof_and_reason(self):
        state = _run_graph(
            source=self.SOURCE,
            executor=MockExecutor(contract_kinds={"vault": "VulnerableVault", "attacker": "ReentrantAttacker"}),
        )
        self.assertEqual(state["stopped_reason"], "verified")
        self.assertEqual(state["final_proof"], state["verifier_verdict"].proof_artifact)

    def test_exhaustion_sets_reason_and_clears_proof(self):
        state = _run_graph(
            source=self.SOURCE,
            executor=MockExecutor(contract_kinds={"vault": "SafeVault", "attacker": "ReentrantAttacker"}),
        )
        self.assertEqual(state["stopped_reason"], "max_retries (1) exhausted without verification")
        self.assertIsNone(state["final_proof"])

    def test_missing_scenario_preserves_planner_error_and_clears_proof(self):
        state = _run_graph(source="contract Empty {}", executor=MockExecutor(contract_kinds={}))
        self.assertEqual(state["stopped_reason"], "no hypotheses to plan from")
        self.assertIsNone(state["final_proof"])

    def test_langgraph_attempt_count_matches_executions(self):
        """Fix 8b (CodeRabbit on PR #30): A09 was incomplete in the
        LangGraph backend — the critic only runs before a retry, so the
        first successful execution returned attempt_count 0, and an
        exhausted run reported 3 for 4 executions."""
        state = _run_graph(
            source=self.SOURCE,
            executor=MockExecutor(contract_kinds={"vault": "VulnerableVault", "attacker": "ReentrantAttacker"}),
        )
        self.assertEqual(state["attempt_count"], 1)

    def test_langgraph_exhausted_run_counts_all_executions(self):
        state = _run_graph(
            source=self.SOURCE,
            executor=MockExecutor(contract_kinds={"vault": "SafeVault", "attacker": "ReentrantAttacker"}),
            max_retries=3,
        )
        self.assertEqual(state["attempt_count"], 4)
        self.assertEqual(state["stopped_reason"], "max_retries (3) exhausted without verification")

    def test_all_node_written_keys_are_declared_in_state(self):
        """Fix 8c (CodeRabbit Major on PR #30): every key a node writes must
        be declared in ShadowStrikeState — in real LangGraph a node writes
        only to declared state channels, so an undeclared
        _critic_adjustment is dropped and the planner never receives the
        critic's adjustment, silently disabling A08 in this backend."""
        from shadow_strike.agent.graph_langgraph import ShadowStrikeState

        declared = set(ShadowStrikeState.__annotations__)
        for key in (
            "_critic_adjustment",
            "_llm_critic_notes",
            "_llm_hypothesis_notes",
            "_recon_functions",
            "_recon_sensitive_calls",
        ):
            self.assertIn(key, declared)

    @unittest.skipUnless(
        importlib.util.find_spec("langgraph") is not None, "real langgraph package not installed"
    )
    def test_real_langgraph_critic_adjustment_reaches_planner(self):
        """Fix 8c: with the REAL langgraph package (not the fake harness),
        the critic's increase_attacker_eth adjustment must reach the
        planner — the retry scenario's attacker ETH doubles from 1.0 to
        2.0. Before the fix the undeclared _critic_adjustment was dropped
        by the state schema and the retry ran with the original 1.0 ETH.

        The fake harness in this file leaks into sys.modules between
        tests, so the module is re-imported here with the fake removed —
        and the StateGraph identity is asserted, so a leaked fake fails
        loudly instead of passing silently."""
        module_name = "shadow_strike.agent.graph_langgraph"
        for name in (module_name, "langgraph", "langgraph.graph"):
            sys.modules.pop(name, None)
        importlib.import_module("langgraph")
        graph_module = importlib.import_module(module_name)
        self.assertTrue(
            graph_module.StateGraph.__module__.startswith("langgraph"),
            f"expected the real langgraph StateGraph, got {graph_module.StateGraph}",
        )
        graph = graph_module.build_graph(
            executor=MockExecutor(contract_kinds={"vault": "SafeVault", "attacker": "ReentrantAttacker"}),
            verifier=Verifier(),
            library=AttackLibrary(),
            llm_fn=lambda prompt: "increase_attacker_eth",
            max_retries=3,
            target_contracts={"vault": "0xabc"},
        )
        state = graph.invoke({
            "target_contract_source": self.SOURCE,
            "target_protocol_name": "GraphTestVault",
            "attempt_count": 0,
            "history": [],
        })
        self.assertEqual(state["current_scenario"].attacker.initial_eth, 2.0)
        self.assertEqual(state["attempt_count"], 4)
        self.assertEqual(state["stopped_reason"], "max_retries (3) exhausted without verification")


if __name__ == "__main__":
    unittest.main()
