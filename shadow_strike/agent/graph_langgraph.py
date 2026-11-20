"""
shadow_strike.agent.graph_langgraph
======================================
Production orchestrator using LangGraph's StateGraph. Requires:
    pip install langgraph

Semantically identical to graph_simple.SimpleShadowStrikeGraph — same
nodes, same edges, same retry-bound. Use this version when you want
LangGraph's built-in checkpointing, time-travel debugging, and
streaming, which matter once Shadow Strike is driven by a real LLM
making non-deterministic choices (the whole reason to persist
intermediate state between steps).
"""

from __future__ import annotations

from typing import Any, TypedDict

try:
    from langgraph.graph import END, StateGraph
except ImportError as e:
    raise ImportError(
        "graph_langgraph.py requires the `langgraph` package: pip install langgraph. "
        "For a zero-dependency alternative with identical semantics, use "
        "shadow_strike.agent.graph_simple.SimpleShadowStrikeGraph instead."
    ) from e

from shadow_strike.agent.nodes import (
    _effective_max_retries,
    critic_node,
    executor_node,
    hypothesis_node,
    recon_node,
    scenario_planner_node,
    verifier_node,
)


class ShadowStrikeState(TypedDict, total=False):
    target_contract_source: str
    target_protocol_name: str
    recon_notes: str
    hypotheses: list[dict]
    current_scenario: Any
    execution_result: Any
    verifier_verdict: Any
    attempt_count: int
    history: list[dict]
    final_proof: dict | None
    planner_error: str | None


def build_graph(executor, verifier=None, library=None, llm_fn=None, max_retries: int = 3,
                 fork_url: str = "", fork_block: int = 0, target_contracts: dict[str, str] | None = None,
                 attacker_initial_eth: float = 1.0):
    target_contracts = target_contracts or {}

    graph = StateGraph(ShadowStrikeState)

    graph.add_node("recon", recon_node)
    graph.add_node("hypothesis", lambda s: hypothesis_node(s, llm_fn=llm_fn, library=library))
    graph.add_node("scenario_planner", lambda s: scenario_planner_node(
        s, fork_url=fork_url, fork_block=fork_block, target_contracts=target_contracts,
        attacker_initial_eth=attacker_initial_eth, llm_fn=llm_fn, library=library,
    ))
    graph.add_node("executor", lambda s: executor_node(s, executor))
    graph.add_node("verifier", lambda s: verifier_node(s, verifier))
    graph.add_node("critic", lambda s: critic_node(s, llm_fn=llm_fn))

    graph.set_entry_point("recon")
    graph.add_edge("recon", "hypothesis")
    graph.add_edge("hypothesis", "scenario_planner")

    def after_planner(state: ShadowStrikeState) -> str:
        return "executor" if state.get("current_scenario") is not None else "stop_no_scenario"

    graph.add_conditional_edges("scenario_planner", after_planner, {
        "executor": "executor",
        "stop_no_scenario": END,
    })
    graph.add_edge("executor", "verifier")

    def after_verifier(state: ShadowStrikeState) -> str:
        verdict = state.get("verifier_verdict")
        if verdict is not None and verdict.verified:
            return "success"
        # Part 9: the bound is the tighter of the graph's cap and the
        # scenario's own max_retries.
        if state.get("attempt_count", 0) >= _effective_max_retries(state, max_retries):
            return "give_up"
        return "retry"

    graph.add_conditional_edges("verifier", after_verifier, {
        "success": END,
        "give_up": END,
        "retry": "critic",
    })
    graph.add_edge("critic", "scenario_planner")

    return graph.compile()
