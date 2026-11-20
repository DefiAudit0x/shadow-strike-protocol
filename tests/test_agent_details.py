"""Regressions for source hygiene, planning refinements, and provider boundaries."""

import json
from unittest.mock import MagicMock, patch

import pytest

from shadow_strike.agent import llm_providers
from shadow_strike.agent.graph_simple import SimpleShadowStrikeGraph
from shadow_strike.agent.llm_providers import AnthropicLLM, LLMProviderError
from shadow_strike.agent.nodes import (
    _parse_llm_hypothesis_line,
    critic_node,
    hypothesis_node,
    recon_node,
    scenario_planner_node,
)
from shadow_strike.attack_library.registry import AttackLibrary
from shadow_strike.execution.mock_executor import MockExecutor


def _plan(state, funds=1.0):
    return scenario_planner_node(
        state, fork_url="", fork_block=0, target_contracts={"vault": "0xabc"},
        attacker_initial_eth=funds,
    )["current_scenario"]


def _state(vuln_class="reentrancy"):
    return {"hypotheses": [{"vulnerability_class": vuln_class, "hypothesis": "test"}]}


@pytest.mark.parametrize("source", [
    '// function fake() { unchecked { call{value: 1}(""); }',
    '/* function fake() { unchecked {\n call{value: 1}(""); } */',
    r'''string s = "escaped \" // /* function fake() { unchecked { call{value:";''',
    "string s = 'function fake() { unchecked { call{value:';",
])
def test_a01_non_executable_text_cannot_generate_hypotheses(source):
    state = hypothesis_node(recon_node({"target_contract_source": source}))
    assert state["_recon_functions"] == []
    assert state["_recon_sensitive_calls"] == []
    assert state["hypotheses"] == []


def test_a01_executable_patterns_and_line_numbers_survive():
    source = '/* ignored\n ignored */\nfunction real() external { unchecked { x.call{value: 1}(""); } }'
    state = hypothesis_node(recon_node({"target_contract_source": source}))
    assert state["_recon_functions"] == [("real", "")]
    assert state["_recon_sensitive_calls"][0]["line"] == 3
    classes = {h["vulnerability_class"] for h in state["hypotheses"]}
    assert "reentrancy" in classes
    assert "accounting" in classes


@pytest.mark.parametrize("line", [
    "not_reentrancy: no", "discussion mentions reentrancy: maybe", "reentrancy:",
])
def test_a03_class_field_must_be_exact(line):
    assert _parse_llm_hypothesis_line(line, AttackLibrary()) is None


@pytest.mark.parametrize("prefix", ["", "  ", "- ", "1. "])
def test_a03_delimited_class_field_is_accepted(prefix):
    parsed = _parse_llm_hypothesis_line(prefix + "reentrancy: test", AttackLibrary())
    assert parsed["vulnerability_class"] == "reentrancy"


@pytest.mark.parametrize("vuln_class", ["reentrancy", "oracle_manipulation", "price_manipulation"])
@pytest.mark.parametrize("funds", [0.0, 1e-10, 0.005, 0.05, 1.0])
def test_a05_builder_spending_is_within_declared_funds(vuln_class, funds):
    scenario = _plan(_state(vuln_class), funds)
    spending = sum(s.value_eth for s in scenario.steps if s.caller == "attacker")
    assert spending <= funds
    if vuln_class == "price_manipulation":
        assert scenario.steps[0].args[0] <= max(funds - 1e-9, 0)
    if funds == 1.0:
        assert scenario.steps[0].value_eth == pytest.approx(0.99 if vuln_class == "price_manipulation" else 0.9)


def test_a05_zero_capital_reentrancy_does_not_fail_for_insufficient_balance():
    scenario = _plan(_state(), 0.0)
    result = MockExecutor({"vault": "VulnerableVault", "attacker": "ReentrantAttacker"}).execute(scenario)
    assert "insufficient balance" not in (result.revert_reason or "")


def test_a07_adjustments_accumulate_and_are_consumed_once():
    state = _state()
    assert _plan(state).attacker_max_reentries == 3
    state["_critic_adjustment"] = "increase_attacker_eth"
    assert _plan(state).attacker.initial_eth == 2.0
    state["_critic_adjustment"] = "increase_max_reentries"
    scenario = _plan(state)
    assert (scenario.attacker.initial_eth, scenario.attacker_max_reentries) == (2.0, 5)
    scenario = _plan(state)
    assert (scenario.attacker.initial_eth, scenario.attacker_max_reentries) == (2.0, 5)


def test_a08_llm_critic_adjustment_reaches_next_plan():
    state = _state()
    _plan(state)
    critic_node(state, llm_fn=lambda prompt: "increase_attacker_eth")
    assert state["_llm_critic_notes"] == "increase_attacker_eth"
    assert state["history"][-1]["adjustment_applied"] == "increase_attacker_eth"
    assert _plan(state).attacker.initial_eth == 2.0
    critic_node(state, llm_fn=lambda prompt: "increase_max_reentries")
    scenario = _plan(state)
    assert (scenario.attacker.initial_eth, scenario.attacker_max_reentries) == (2.0, 5)


@pytest.mark.parametrize("reply", ["free-form discussion", TimeoutError("unavailable")])
def test_a08_invalid_llm_output_preserves_rule_based_adjustment(reply):
    state = _state()
    _plan(state)
    state["verifier_verdict"] = MagicMock(verified=False)

    def llm(prompt):
        if isinstance(reply, Exception):
            raise reply
        return reply

    critic_node(state, llm_fn=llm)
    assert _plan(state).attacker_max_reentries == 5


@pytest.mark.parametrize("kind,retries,expected", [
    ("VulnerableVault", 3, 1), ("SafeVault", 0, 1), ("SafeVault", 2, 3), ("SafeVault", 10, 4),
])
def test_a09_attempt_count_matches_executions(kind, retries, expected):
    executor = MockExecutor({"vault": kind, "attacker": "ReentrantAttacker"})
    counts = []
    result = SimpleShadowStrikeGraph(executor, max_retries=retries).run(
        target_contract_source='function withdraw() external { msg.sender.call{value: 1}(""); }',
        target_protocol_name="test", fork_url="", fork_block=0,
        target_contracts={"vault": "0xabc"},
        on_step=lambda label, state: counts.append(state["attempt_count"]) if label == "executor" else None,
    )
    assert counts == list(range(1, expected + 1))
    assert result["attempt_count"] == expected
    assert [h["attempt"] for h in result["history"]] == list(range(1, expected))


@pytest.mark.parametrize("response", [
    TimeoutError("timed out"), b"invalid json", b'[]', b'{"content": [1]}',
    b'{"content": [{"type": "text"}]}', b'{"content": [{"type": "text", "text": 1}]}',
])
def test_a11_provider_errors_use_custom_type(response):
    with patch("urllib.request.urlopen") as urlopen:
        if isinstance(response, Exception):
            urlopen.side_effect = response
        else:
            urlopen.return_value.__enter__.return_value.read.return_value = response
        with pytest.raises(LLMProviderError):
            AnthropicLLM(api_key="test")("prompt")


def test_a11_provider_valid_text_blocks():
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps({
        "content": [{"type": "text", "text": "first"}, {"type": "text", "text": "second"}],
    }).encode()
    with patch("urllib.request.urlopen", return_value=response):
        assert AnthropicLLM(api_key="test")("prompt") == "first\nsecond"


def test_a11_provider_header_acknowledges_mocked_tests():
    assert "NOT exercised by the test suite" not in llm_providers.__doc__
