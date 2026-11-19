"""
Self-contained test suite — stdlib unittest, zero extra deps beyond
what the core engine already needs (jinja2, pyyaml).

Run: PYTHONPATH=. python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import unittest

from shadow_strike.agent.graph_simple import SimpleShadowStrikeGraph
from shadow_strike.attack_library.registry import AttackLibrary
from shadow_strike.core.models import (
    AttackerModel,
    AttackScenario,
    InitialState,
    ShadowStrikeValidationError,
    SuccessCondition,
    TransactionStep,
)
from shadow_strike.core.safe_eval import UnsafeExpressionError, safe_eval
from shadow_strike.execution.compiler import ScenarioCompiler
from shadow_strike.execution.mock_executor import MockExecutor
from shadow_strike.storage.db import KnowledgeStore
from shadow_strike.verifier.verifier import Verifier


def _make_scenario(**overrides):
    base = {
        "vulnerability_class": "reentrancy",
        "target_protocol": "TestVault",
        "hypothesis": "test hypothesis",
        "attacker": AttackerModel(initial_eth=1.0),
        "initial_state": InitialState(
            fork_url="https://example/rpc", fork_block=1,
            target_contracts={"vault": "0xabc"},
            balances={"vault": 9.0},
        ),
        "steps": [
            TransactionStep(step_id=1, caller="attacker", target="vault", function="deposit()", value_eth=0.9),
            TransactionStep(step_id=2, caller="attacker", target="attacker", function="attack()"),
        ],
        "success_conditions": [
            SuccessCondition(
                expression="attacker.eth_balance_after - attacker.eth_balance_before > attacker.legitimate_entitlement",
                description="profited",
            )
        ],
    }
    base.update(overrides)
    return AttackScenario(**base)


class TestScenarioValidation(unittest.TestCase):
    def test_valid_scenario_constructs(self):
        s = _make_scenario()
        self.assertEqual(s.vulnerability_class.value, "reentrancy")

    def test_empty_steps_rejected(self):
        with self.assertRaises(ShadowStrikeValidationError):
            _make_scenario(steps=[])

    def test_no_success_conditions_rejected(self):
        with self.assertRaises(ShadowStrikeValidationError):
            _make_scenario(success_conditions=[])

    def test_duplicate_step_ids_rejected(self):
        with self.assertRaises(ShadowStrikeValidationError):
            _make_scenario(steps=[
                TransactionStep(step_id=1, caller="attacker", target="vault", function="deposit()"),
                TransactionStep(step_id=1, caller="attacker", target="attacker", function="attack()"),
            ])

    def test_bad_function_signature_rejected(self):
        with self.assertRaises(ShadowStrikeValidationError):
            TransactionStep(step_id=1, caller="attacker", target="vault", function="deposit")  # no parens

    def test_roundtrip_json(self):
        s = _make_scenario()
        restored = AttackScenario.from_json(s.to_json())
        self.assertEqual(restored.scenario_id, s.scenario_id)
        self.assertEqual(len(restored.steps), len(s.steps))


class TestSafeEval(unittest.TestCase):
    def test_basic_arithmetic_and_compare(self):
        ctx = {"a": {"x": 10}, "b": {"x": 3}}
        self.assertTrue(safe_eval("a.x - b.x > 5", ctx))
        self.assertFalse(safe_eval("a.x < b.x", ctx))

    def test_rejects_function_calls(self):
        with self.assertRaises(UnsafeExpressionError):
            safe_eval("len([1,2,3])", {})

    def test_rejects_import_injection(self):
        with self.assertRaises(UnsafeExpressionError):
            safe_eval("__import__('os').system('id')", {})

    def test_rejects_unknown_identifier(self):
        with self.assertRaises(UnsafeExpressionError):
            safe_eval("nonexistent.value > 0", {})

    def test_rejects_huge_exponent_dos(self):
        with self.assertRaises(UnsafeExpressionError):
            safe_eval("2 ** 999999", {})


class TestAttackLibrary(unittest.TestCase):
    def test_reentrancy_class_registered(self):
        lib = AttackLibrary()
        self.assertIn("reentrancy", lib.available_classes())

    def test_unknown_class_raises(self):
        lib = AttackLibrary()
        with self.assertRaises(KeyError):
            lib.get("not_a_real_class")


class TestCompiler(unittest.TestCase):
    def test_compiles_to_nonempty_solidity(self):
        s = _make_scenario()
        compiler = ScenarioCompiler(target_types={"vault": "IVault"})
        source = compiler.compile(s, attacker_contract_name="Mal", attacker_import_path="./Mal.sol")
        self.assertIn("pragma solidity", source)
        self.assertIn(s.scenario_id, source)
        self.assertIn("vm.createSelectFork", source)


class TestMockExecutorAndVerifier(unittest.TestCase):
    def test_vulnerable_vault_is_exploitable(self):
        s = _make_scenario()
        executor = MockExecutor(contract_kinds={"vault": "VulnerableVault", "attacker": "ReentrantAttacker"})
        result = executor.execute(s)
        verdict = Verifier().verify(s, result)
        self.assertTrue(verdict.verified)
        self.assertGreater(
            result.state_vars["attacker"]["eth_balance_after"],
            result.state_vars["attacker"]["eth_balance_before"],
        )

    def test_safe_vault_resists_same_scenario(self):
        s = _make_scenario()
        executor = MockExecutor(contract_kinds={"vault": "SafeVault", "attacker": "ReentrantAttacker"})
        result = executor.execute(s)
        verdict = Verifier().verify(s, result)
        self.assertFalse(verdict.verified)

    def test_mock_engine_stamped_on_result(self):
        s = _make_scenario()
        executor = MockExecutor(contract_kinds={"vault": "VulnerableVault", "attacker": "ReentrantAttacker"})
        result = executor.execute(s)
        self.assertEqual(result.engine, "mock")


class TestFullGraph(unittest.TestCase):
    def test_graph_finds_and_verifies_reentrancy(self):
        source = """
        contract Vault {
            function withdraw() external {
                (bool ok,) = msg.sender.call{value: 1}("");
            }
        }
        """
        executor = MockExecutor(contract_kinds={"vault": "VulnerableVault", "attacker": "ReentrantAttacker"})
        graph = SimpleShadowStrikeGraph(executor=executor, verifier=Verifier(), library=AttackLibrary(), max_retries=3)
        result = graph.run(
            target_contract_source=source,
            target_protocol_name="InlineTestVault",
            fork_url="", fork_block=0,
            target_contracts={"vault": "0xdead"},
            attacker_initial_eth=1.0,
        )
        self.assertEqual(result["stopped_reason"], "verified")
        self.assertIsNotNone(result["final_proof"])


class TestKnowledgeStore(unittest.TestCase):
    def test_full_write_cycle(self):
        store = KnowledgeStore(db_path=":memory:")
        s = _make_scenario()
        store.save_scenario(s)
        attempt_id = store.save_attempt(
            scenario_id=s.scenario_id, attempt_number=1, status="success",
            failure_reason=None, execution_result={"x": 1}, verifier_result={"verified": True},
        )
        proof_id = store.save_proof(attempt_id=attempt_id, proof_artifact={"ok": True})
        rows = store.attempts_for_scenario(s.scenario_id)
        self.assertEqual(len(rows), 1)
        self.assertTrue(proof_id.startswith("proof_"))


if __name__ == "__main__":
    unittest.main()
