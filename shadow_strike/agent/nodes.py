"""
shadow_strike.agent.nodes
===========================
The six nodes of the reasoning loop. Strict separation enforced here:

  - recon_node, hypothesis_node, scenario_planner_node, critic_node:
    may call an LLM (pluggable via `llm_fn`); if no `llm_fn` is given
    they fall back to a deterministic, rule-based heuristic so the
    whole graph is runnable offline / in CI / in this sandbox with NO
    API key and NO network call.

  - executor_node, verifier_node: NEVER call an LLM, full stop. They
    are thin wrappers around shadow_strike.execution.* and
    shadow_strike.verifier.verifier.Verifier. This is the hard
    boundary described in architecture §2.2 / §0 principle #2.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from shadow_strike.attack_library.registry import AttackLibrary
from shadow_strike.core.models import (
    AttackerModel,
    AttackScenario,
    InitialState,
    SuccessCondition,
    TransactionStep,
    VulnerabilityClass,
)
from shadow_strike.execution.foundry_runner import execute_scenario
from shadow_strike.verifier.verifier import Verifier

LLMFn = Callable[[str], str]   # prompt -> completion; plug in a real model client here


# ---------------------------------------------------------------------
# 1. recon
# ---------------------------------------------------------------------
def recon_node(state: dict) -> dict:
    source = state["target_contract_source"]
    functions = re.findall(r"function\s+(\w+)\s*\(([^)]*)\)", source)
    sensitive_calls = []
    for lineno, line in enumerate(source.splitlines(), 1):
        if "call{value" in line or ".transfer(" in line or ".send(" in line:
            sensitive_calls.append({"line": lineno, "text": line.strip()})

    state["recon_notes"] = (
        f"found {len(functions)} function(s): {[f[0] for f in functions]}; "
        f"{len(sensitive_calls)} low-level value-carrying call(s)"
    )
    state["_recon_functions"] = functions
    state["_recon_sensitive_calls"] = sensitive_calls
    return state


# ---------------------------------------------------------------------
# 2. hypothesis generation
# ---------------------------------------------------------------------
def _parse_llm_hypothesis_line(line: str, library: AttackLibrary) -> dict | None:
    """Parse one LLM output line of the form '<class>: <text>' into a
    hypothesis dict (Part 10). The class must be one the attack library
    knows, and the text must be non-empty; anything else returns None so
    free-form LLM prose never becomes a hypothesis the planner must act on."""
    text = line.strip()
    if not text:
        return None
    for vc in library.available_classes():
        marker = f"{vc}:"
        idx = text.find(marker)
        if idx != -1:
            hypothesis = text[idx + len(marker):].strip()
            if hypothesis:
                return {
                    "vulnerability_class": vc,
                    "hypothesis": hypothesis,
                    "confidence_note": "LLM-proposed — NOT a verdict, see architecture §0 principle #2",
                }
    return None


def hypothesis_node(state: dict, llm_fn: LLMFn | None = None, library: AttackLibrary | None = None) -> dict:
    library = library or AttackLibrary()
    source = state["target_contract_source"]
    hypotheses = []

    for vuln_class in library.available_classes():
        for pat in library.heuristic_patterns(vuln_class):
            if pat["pattern"] in source:
                hypotheses.append({
                    "vulnerability_class": vuln_class,
                    "hypothesis": (
                        f"source contains pattern {pat['pattern']!r} ({pat['note']}) "
                        f"— worth constructing an executable scenario to test"
                    ),
                    "confidence_note": "heuristic pattern match only — NOT a verdict, see architecture §0 principle #2",
                })

    # a plugged-in LLM can refine/add to this list; heuristic hits are
    # always kept too, since the LLM augments, never replaces, recon.
    # The prompt specifies the '<class>: <text>' line format the parser
    # below expects, so a provider's free-form output stays parseable.
    if llm_fn is not None:
        try:
            llm_notes = llm_fn(
                f"Given this recon summary: {state['recon_notes']}\n"
                "Suggest additional vulnerability hypotheses, one per line, each as "
                "'<vulnerability_class>: <one-sentence hypothesis>'. "
                "Example: reentrancy: withdraw() sends ETH before updating the balance."
            )
        except Exception:  # noqa: BLE001 — any provider failure degrades to heuristics, not a crash
            # A provider that fails mid-run degrades to heuristics instead
            # of crashing the run (Part 10).
            llm_notes = None
        state["_llm_hypothesis_notes"] = llm_notes
        if llm_notes:
            seen = {(h["vulnerability_class"], h["hypothesis"]) for h in hypotheses}
            for line in llm_notes.splitlines():
                parsed = _parse_llm_hypothesis_line(line, library)
                if parsed is not None and (parsed["vulnerability_class"], parsed["hypothesis"]) not in seen:
                    seen.add((parsed["vulnerability_class"], parsed["hypothesis"]))
                    hypotheses.append(parsed)

    state["hypotheses"] = hypotheses
    return state


# ---------------------------------------------------------------------
# 3. scenario planning — turns ONE chosen hypothesis into a validated
#    AttackScenario. This is the only node allowed to construct
#    AttackScenario objects, which is what gives scenario_planner_node
#    its "gatekeeper" role: whatever it emits MUST pass
#    AttackScenario.__post_init__ validation before continuing.
#
# Builders are registered per vulnerability_class in SCENARIO_BUILDERS
# below. Adding a new buildable class = adding one function + one
# registry entry — nothing else in the planner changes. A class with
# no registered builder receives an explicit unsupported_class verdict;
# the planner never guesses at a scenario shape — see architecture §4.
# ---------------------------------------------------------------------
def _build_reentrancy_scenario(chosen, target_contracts, attacker_initial_eth, fork_url, fork_block,
                                library, protocol_name, state) -> AttackScenario:
    primary_alias = next(iter(target_contracts))
    deposit_amount = max(attacker_initial_eth - 0.1, 0.1)
    default_sc = library.default_success_conditions("reentrancy")
    default_inv = library.default_invariants("reentrancy")

    return AttackScenario(
        vulnerability_class="reentrancy",
        target_protocol=protocol_name,
        hypothesis=chosen["hypothesis"],
        attacker=AttackerModel(initial_eth=attacker_initial_eth),
        initial_state=InitialState(
            fork_url=fork_url, fork_block=fork_block, target_contracts=target_contracts,
            # other depositors' pooled liquidity already sitting in the vault —
            # without this there'd be nothing beyond the attacker's own deposit
            # to drain. A real recon pass would read this from forked chain state.
            balances={primary_alias: max(attacker_initial_eth * 9, 5.0)},
        ),
        steps=[
            TransactionStep(step_id=1, caller="attacker", target=primary_alias,
                             function="deposit()", value_eth=deposit_amount,
                             comment="establish a legitimate position to withdraw against"),
            TransactionStep(step_id=2, caller="attacker", target="attacker", function="attack()",
                             comment="trigger withdraw(); reentry happens inside the receive() callback"),
        ],
        success_conditions=[SuccessCondition(**sc) for sc in (default_sc or [{
            "expression": "attacker.eth_balance_after - attacker.eth_balance_before > attacker.legitimate_entitlement",
            "description": "attacker extracted more ETH than they legitimately deposited",
        }])],
        invariants_under_test=default_inv,
    )


def _build_access_control_scenario(chosen, target_contracts, attacker_initial_eth, fork_url, fork_block,
                                    library, protocol_name, state) -> AttackScenario:
    primary_alias = next(iter(target_contracts))
    default_sc = library.default_success_conditions("access_control")
    default_inv = library.default_invariants("access_control")

    # Library defaults are written against a `{target}` placeholder and
    # resolved here to this scenario's primary alias: the mock emits
    # per-contract state (last_caller, privileged_state) under the
    # contract's alias, and a literal alias in meta.yaml would only
    # verify when the target happened to be named that way (P1-2).
    raw_sc = default_sc or [{
        "expression": f"{primary_alias}.last_caller == 'attacker'",
        "description": "unauthorized caller successfully invoked the privileged function",
    }]
    success_conditions = [
        SuccessCondition(
            expression=sc["expression"].replace("{target}", primary_alias),
            description=sc["description"],
        )
        for sc in raw_sc
    ]
    invariants = [inv.replace("{target}", primary_alias) for inv in default_inv]

    return AttackScenario(
        vulnerability_class="access_control",
        target_protocol=protocol_name,
        hypothesis=chosen["hypothesis"],
        attacker=AttackerModel(initial_eth=attacker_initial_eth),
        initial_state=InitialState(fork_url=fork_url, fork_block=fork_block, target_contracts=target_contracts),
        steps=[
            TransactionStep(step_id=1, caller="attacker", target=primary_alias, function="privilegedAction()",
                             comment="call a privileged function directly, as an unauthorized caller"),
        ],
        success_conditions=success_conditions,
        invariants_under_test=invariants,
    )


def _build_initialization_scenario(chosen, target_contracts, attacker_initial_eth, fork_url, fork_block,
                                    library, protocol_name, state) -> AttackScenario:
    primary_alias = next(iter(target_contracts))
    return AttackScenario(
        vulnerability_class="initialization",
        target_protocol=protocol_name,
        hypothesis=chosen["hypothesis"],
        attacker=AttackerModel(initial_eth=attacker_initial_eth),
        initial_state=InitialState(fork_url=fork_url, fork_block=fork_block, target_contracts=target_contracts),
        steps=[
            TransactionStep(step_id=1, caller="attacker", target=primary_alias, function="initialize()",
                             comment="front-run the real deployer's initialize() call"),
        ],
        success_conditions=[SuccessCondition(
            expression=f"{primary_alias}.owner == 'attacker'",
            description="attacker front-ran initialization and became the privileged owner",
        )],
    )


def _build_oracle_manipulation_scenario(chosen, target_contracts, attacker_initial_eth, fork_url, fork_block,
                                         library, protocol_name, state) -> AttackScenario:
    # expects target_contracts to name the pool AND the market, e.g.
    # {"pool": "0x...", "market": "0x..."}; falls back to generic aliases
    pool_alias = next((a for a in target_contracts if "pool" in a.lower()), next(iter(target_contracts)))
    market_alias = next((a for a in target_contracts if "market" in a.lower() or "lend" in a.lower()),
                         list(target_contracts)[-1])
    default_sc = library.default_success_conditions("oracle_manipulation")
    default_inv = library.default_invariants("oracle_manipulation")
    swap_amount = max(attacker_initial_eth * 0.9, 0.1)

    return AttackScenario(
        vulnerability_class="oracle_manipulation",
        target_protocol=protocol_name,
        hypothesis=chosen["hypothesis"],
        attacker=AttackerModel(initial_eth=attacker_initial_eth),
        initial_state=InitialState(fork_url=fork_url, fork_block=fork_block, target_contracts=target_contracts),
        steps=[
            TransactionStep(step_id=1, caller="attacker", target="attacker", function="attack()",
                             value_eth=swap_amount,
                             comment=f"swap into {pool_alias} to move spot price, then borrow against "
                                     f"the inflated valuation from {market_alias} in the same logical tx"),
        ],
        success_conditions=[SuccessCondition(**sc) for sc in (default_sc or [{
            "expression": "attacker.eth_balance_after - attacker.eth_balance_before > 0",
            "description": "attacker extracted value purely from a manipulated price read",
        }])],
        invariants_under_test=default_inv,
    )


def _build_signature_replay_scenario(chosen, target_contracts, attacker_initial_eth, fork_url, fork_block,
                                      library, protocol_name, state) -> AttackScenario:
    primary_alias = next(iter(target_contracts))
    return AttackScenario(
        vulnerability_class="signature_replay",
        target_protocol=protocol_name,
        hypothesis=chosen["hypothesis"],
        attacker=AttackerModel(initial_eth=attacker_initial_eth),
        initial_state=InitialState(fork_url=fork_url, fork_block=fork_block, target_contracts=target_contracts),
        steps=[
            TransactionStep(step_id=1, caller="attacker", target=primary_alias, function="executeSignedAction()",
                             args=["captured-sig-1"], comment="legitimate first use of a captured signature"),
            TransactionStep(step_id=2, caller="attacker", target=primary_alias, function="executeSignedAction()",
                             args=["captured-sig-1"], comment="replay of the SAME signature"),
        ],
        success_conditions=[SuccessCondition(
            expression=f"{primary_alias}.replay_count > 1",
            description="the same signed authorization was consumed more than once",
        )],
    )


def _build_price_manipulation_scenario(chosen, target_contracts, attacker_initial_eth, fork_url, fork_block,
                                        library, protocol_name, state) -> AttackScenario:
    primary_alias = next(iter(target_contracts))
    donation = max(attacker_initial_eth - 0.01, 0.01)
    return AttackScenario(
        vulnerability_class="price_manipulation",
        target_protocol=protocol_name,
        hypothesis=chosen["hypothesis"],
        attacker=AttackerModel(initial_eth=attacker_initial_eth),
        initial_state=InitialState(fork_url=fork_url, fork_block=fork_block, target_contracts=target_contracts,
                                   balances={"victim": 1.0}),
        steps=[
            TransactionStep(step_id=1, caller="attacker", target="attacker", function="attack()",
                             value_eth=donation, args=[donation],
                             comment="seed deposit for 1 share, then donate directly to inflate share price"),
            # the actual exploit signature only shows up once a REAL
            # depositor interacts post-manipulation — checking total_shares
            # right after the attack alone doesn't distinguish a resistant
            # vault from a vulnerable one (both start near-zero); this
            # victim deposit is what the success condition actually judges.
            TransactionStep(step_id=2, caller="victim", target=primary_alias, function="deposit()",
                             value_eth=1.0, comment="a legitimate user deposits after the manipulation"),
        ],
        success_conditions=[SuccessCondition(
            expression=f"{primary_alias}.victim_shares < 0.01",
            description="a legitimate depositor received near-zero shares for a real 1 ETH deposit "
                        "(classic inflation-attack signature)",
        )],
    )


SCENARIO_BUILDERS = {
    VulnerabilityClass.REENTRANCY.value: _build_reentrancy_scenario,
    VulnerabilityClass.ACCESS_CONTROL.value: _build_access_control_scenario,
    VulnerabilityClass.ORACLE_MANIPULATION.value: _build_oracle_manipulation_scenario,
    VulnerabilityClass.INITIALIZATION.value: _build_initialization_scenario,
    VulnerabilityClass.SIGNATURE_REPLAY.value: _build_signature_replay_scenario,
    VulnerabilityClass.PRICE_MANIPULATION.value: _build_price_manipulation_scenario,
}


def scenario_planner_node(
    state: dict,
    fork_url: str,
    fork_block: int,
    target_contracts: dict[str, str],
    attacker_initial_eth: float = 1.0,
    llm_fn: LLMFn | None = None,
    library: AttackLibrary | None = None,
) -> dict:
    library = library or AttackLibrary()
    if not state["hypotheses"]:
        state["current_scenario"] = None
        state["planner_error"] = "no hypotheses to plan from"
        state["verdict"] = "error"
        return state

    chosen = state["hypotheses"][0]
    vuln_class = chosen["vulnerability_class"]
    builder = SCENARIO_BUILDERS.get(vuln_class)

    if builder is None:
        # Refuse to guess a scenario shape it has no template for. This is
        # a clean unsupported-class outcome, not a planner failure.
        state["current_scenario"] = None
        state.pop("planner_error", None)
        state["planner_detail"] = f"no scenario builder registered yet for {vuln_class!r}"
        state["verdict"] = "unsupported_class"
        state["stopped_reason"] = "unsupported_class"
        return state

    scenario = builder(
        chosen, target_contracts, attacker_initial_eth, fork_url, fork_block,
        library, state.get("target_protocol_name", "unknown_target"), state,
    )

    # if a critic suggestion exists from a prior failed attempt, apply it
    adjustment = state.get("_critic_adjustment")
    if adjustment == "increase_attacker_eth":
        scenario.attacker.initial_eth *= 2
        if scenario.steps and scenario.steps[0].function.startswith(("deposit", "attack")):
            scenario.steps[0].value_eth = max(scenario.attacker.initial_eth - 0.1, 0.1)
    elif adjustment == "increase_max_reentries":
        # The override used to be written to state["_max_reentries_override"],
        # which nothing ever read. The adjustment now lives on the scenario
        # itself, and the mock executor reads it when constructing the
        # attacker (Part 9).
        scenario.attacker_max_reentries += 2

    state["current_scenario"] = scenario
    return state


# ---------------------------------------------------------------------
# 4. executor — NO LLM. Thin dispatcher to whichever executor backend
#    was configured (MockExecutor for offline/demo, ForgeRunner for prod).
# ---------------------------------------------------------------------
def executor_node(state: dict, executor) -> dict:
    scenario = state["current_scenario"]
    if scenario is None:
        state["execution_result"] = None
        return state
    result = execute_scenario(executor, scenario)
    state["execution_result"] = result
    return state


# ---------------------------------------------------------------------
# 5. verifier — NO LLM.
# ---------------------------------------------------------------------
def verifier_node(state: dict, verifier: Verifier | None = None) -> dict:
    verifier = verifier or Verifier()
    scenario = state["current_scenario"]
    execution_result = state["execution_result"]
    if scenario is None or execution_result is None:
        state["verifier_verdict"] = None
        return state
    verdict = verifier.verify(scenario, execution_result)
    state["verifier_verdict"] = verdict
    state["verdict"] = verdict.verdict
    return state


def _effective_max_retries(state: dict, default: int) -> int:
    """Retry bound for the graph loop (Part 9).

    The scenario carries its own max_retries; the graph has its own
    constructor default. The loop stops at whichever bound is tighter, so
    a scenario that asks for fewer retries is honoured and the graph's
    operator cap still holds when the scenario asks for more.
    """
    scenario = state.get("current_scenario")
    if scenario is not None:
        return min(default, scenario.max_retries)
    return default


# ---------------------------------------------------------------------
# 6. critic — analyzes a failed attempt and proposes ONE concrete
#    adjustment. Rule-based fallback mirrors what a prompted LLM would
#    plausibly suggest, so the retry loop is demonstrable offline.
# ---------------------------------------------------------------------
def critic_node(state: dict, llm_fn: LLMFn | None = None) -> dict:
    verdict = state.get("verifier_verdict")
    execution_result = state.get("execution_result")
    state["attempt_count"] = state.get("attempt_count", 0) + 1

    reason = "unknown"
    adjustment = None
    if execution_result and execution_result.reverted:
        reason = execution_result.revert_reason or "reverted"
        if "insufficient balance" in (reason or ""):
            adjustment = "increase_attacker_eth"
    elif verdict and not verdict.verified:
        reason = "success_conditions not met"
        adjustment = "increase_max_reentries"

    # Do not repeat a failed adjustment: if an earlier attempt already
    # tried this adjustment and still failed, there is nothing new to try
    # (Part 9 — the critic reads state["history"]).
    if adjustment is not None:
        tried = [h.get("adjustment_applied") for h in state.get("history", [])]
        if adjustment in tried:
            adjustment = None

    state["history"] = state.get("history", []) + [{
        "attempt": state["attempt_count"],
        "scenario_id": state["current_scenario"].scenario_id if state.get("current_scenario") else None,
        "reason": reason,
        "adjustment_applied": adjustment,
    }]
    state["_critic_adjustment"] = adjustment

    if llm_fn is not None:
        try:
            state["_llm_critic_notes"] = llm_fn(
                f"Attempt {state['attempt_count']} failed: {reason}. "
                f"Trace: {execution_result.call_trace if execution_result else 'n/a'}. "
                f"Suggest one concrete scenario adjustment."
            )
        except Exception:  # noqa: BLE001 — any provider failure degrades, not a crash
            # A provider that fails mid-run degrades instead of crashing
            # the run (Part 10); the rule-based adjustment above stands.
            state["_llm_critic_notes"] = "LLM unavailable; degraded to the rule-based adjustment."
    return state
