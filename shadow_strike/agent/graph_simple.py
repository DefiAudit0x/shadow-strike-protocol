"""
shadow_strike.agent.graph_simple
===================================
Zero-dependency orchestrator implementing the exact same node sequence
as graph_langgraph.py's StateGraph:

    recon -> hypothesis -> scenario_planner -> executor -> verifier
         -> (success: END) | (failure: critic -> scenario_planner, bounded by max_retries)

Use this when you don't want the `langgraph` dependency (CI, this
sandbox, quick scripts). Swap to ShadowStrikeLangGraph for production
if you want LangGraph's checkpointing / visualization / streaming.
"""

from __future__ import annotations

from shadow_strike.agent.nodes import (
    _effective_max_retries,
    critic_node,
    executor_node,
    hypothesis_node,
    recon_node,
    scenario_planner_node,
    verifier_node,
)


class SimpleShadowStrikeGraph:
    def __init__(self, executor, verifier=None, library=None, llm_fn=None, max_retries: int = 3):
        self.executor = executor
        self.verifier = verifier
        self.library = library
        self.llm_fn = llm_fn
        self.max_retries = max_retries

    def run(
        self,
        target_contract_source: str,
        target_protocol_name: str,
        fork_url: str,
        fork_block: int,
        target_contracts: dict[str, str],
        attacker_initial_eth: float = 1.0,
        on_step=None,
    ) -> dict:
        state: dict = {
            "target_contract_source": target_contract_source,
            "target_protocol_name": target_protocol_name,
            "attempt_count": 0,
            "_counts_executed_attempts": True,
            "history": [],
        }

        def emit(label):
            if on_step:
                on_step(label, state)

        state = recon_node(state)
        emit("recon")

        state = hypothesis_node(state, llm_fn=self.llm_fn, library=self.library)
        emit("hypothesis")

        while True:
            state = scenario_planner_node(
                state,
                fork_url=fork_url,
                fork_block=fork_block,
                target_contracts=target_contracts,
                attacker_initial_eth=attacker_initial_eth,
                llm_fn=self.llm_fn,
                library=self.library,
            )
            emit("scenario_planner")

            if state["current_scenario"] is None:
                state["final_proof"] = None
                state["stopped_reason"] = state.get("stopped_reason") or state.get(
                    "planner_error", "no scenario produced"
                )
                return state

            state = executor_node(state, self.executor)
            state["attempt_count"] += 1
            emit("executor")

            state = verifier_node(state, self.verifier)
            emit("verifier")

            verdict = state["verifier_verdict"]
            if verdict is not None and verdict.verified:
                state["final_proof"] = verdict.proof_artifact
                state["stopped_reason"] = "verified"
                return state

            # Part 9: the bound is the tighter of the graph's cap and the
            # scenario's own max_retries.
            bound = _effective_max_retries(state, self.max_retries)
            if state["attempt_count"] > bound:
                state["final_proof"] = None
                state["stopped_reason"] = f"max_retries ({bound}) exhausted without verification"
                return state

            state = critic_node(state, llm_fn=self.llm_fn)
            emit("critic")
