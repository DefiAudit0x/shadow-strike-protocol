"""
Self-contained test suite — stdlib unittest, zero extra deps beyond
what the core engine already needs (jinja2, pyyaml).

Run: PYTHONPATH=. python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import os
import shutil
import subprocess
import unittest
from argparse import Namespace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from shadow_strike.agent.graph_simple import SimpleShadowStrikeGraph
from shadow_strike.attack_library.registry import AttackLibrary
from shadow_strike.core.models import (
    AttackerModel,
    AttackScenario,
    ExecutionResult,
    InitialState,
    ShadowStrikeValidationError,
    SuccessCondition,
    TransactionStep,
)
from shadow_strike.core.safe_eval import UnsafeExpressionError, safe_eval
from shadow_strike.core.scenario_loader import save_scenario_yaml
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
    def test_c01_invalid_numeric_state_rejected(self):
        constructors = {
            "initial_eth": lambda value: AttackerModel(initial_eth=value),
            "initial_tokens": lambda value: AttackerModel(initial_tokens={"token": value}),
            "value_eth": lambda value: TransactionStep(1, "attacker", "vault", "deposit()", value_eth=value),
            "step_id": lambda value: TransactionStep(value, "attacker", "vault", "deposit()"),
            "fork_block": lambda value: InitialState("", value, {"vault": "0xabc"}),
            "balances": lambda value: InitialState("", 1, {"vault": "0xabc"}, {"vault": value}),
            "max_retries": lambda value: _make_scenario(max_retries=value),
            "attacker_max_reentries": lambda value: _make_scenario(attacker_max_reentries=value),
        }
        for name, construct in constructors.items():
            for value in (float("nan"), float("inf"), -float("inf"), "1", None, [], {}, True):
                with self.subTest(field=name, value=value), self.assertRaises(ShadowStrikeValidationError):
                    construct(value)
            if name != "step_id":
                with self.subTest(field=name, value=-1), self.assertRaises(ShadowStrikeValidationError):
                    construct(-1)
            if name in ("step_id", "fork_block", "max_retries", "attacker_max_reentries"):
                for value in (1.5, 1.0):
                    with self.subTest(field=name, value=value), self.assertRaises(ShadowStrikeValidationError):
                        construct(value)
            construct(0)
            construct(1)

    def test_c01_balance_containers_must_be_mappings(self):
        for value in (None, [], "1"):
            with self.subTest(value=value), self.assertRaises(ShadowStrikeValidationError):
                AttackerModel(initial_tokens=value)
            with self.subTest(value=value), self.assertRaises(ShadowStrikeValidationError):
                InitialState("", 1, {"vault": "0xabc"}, balances=value)

    def test_c01_json_never_emits_nonfinite_numbers(self):
        for value in (float("nan"), float("inf"), -float("inf")):
            for location in ("balance", "args"):
                scenario = _make_scenario()
                if location == "balance":
                    scenario.attacker.initial_eth = value
                else:
                    scenario.steps[0].args = [{"nested": [value]}]
                for options in ({}, {"allow_nan": True}):
                    with (self.subTest(value=value, location=location, options=options),
                          self.assertRaises(ShadowStrikeValidationError)):
                        scenario.to_json(**options)

    def test_c02_malformed_signature_shapes_rejected(self):
        for signature in ("f(()", "f())", "f(,)", "f(uint256,)", "f(,uint256)",
                          "f(uint256,,address)", "1f()", "f()junk", "f(uint256[)",
                          "f(uint256 address)", "f(())", None, 1):
            with self.subTest(signature=signature), self.assertRaises(ShadowStrikeValidationError):
                TransactionStep(1, "attacker", "vault", signature)

    def test_c02_valid_signature_shapes_preserved(self):
        for signature in ("f()", "withdraw(uint256)", "f(address,uint256)",
                          "f(bytes32[],uint256[2])", "f((address,uint256)[],bytes)",
                          "f(((uint256,bool),bytes32)[2][],address)"):
            with self.subTest(signature=signature):
                TransactionStep(1, "attacker", "vault", signature)

    def test_c03_nonstring_success_condition_rejected(self):
        for expression in (1, None, [], {}, True):
            with self.subTest(expression=expression), self.assertRaisesRegex(
                ShadowStrikeValidationError, "expression must be a string"
            ):
                SuccessCondition(expression, "invalid")

    def test_c04_invalid_vulnerability_class_rejected(self):
        for value in ("invalid", None, 1, [], {}):
            with self.subTest(value=value), self.assertRaisesRegex(
                ShadowStrikeValidationError, "invalid vulnerability_class"
            ):
                _make_scenario(vulnerability_class=value)

    def test_c05_missing_required_fields_reported(self):
        for name in ("attacker", "initial_state", "steps", "success_conditions"):
            data = _make_scenario().to_dict()
            del data[name]
            with self.subTest(field=name), self.assertRaisesRegex(
                ShadowStrikeValidationError, f"missing required field: {name}"
            ):
                AttackScenario.from_dict(data)

    def test_c05_invalid_nested_structure_wrapped(self):
        for field in ("attacker", "initial_state", "steps", "success_conditions"):
            for value in (None, 1, "invalid", [1], {"unknown": 1}):
                data = _make_scenario().to_dict()
                data[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ShadowStrikeValidationError):
                    AttackScenario.from_dict(data)
        data = _make_scenario().to_dict()
        data["attacker"]["unknown"] = 1
        with self.assertRaises(ShadowStrikeValidationError):
            AttackScenario.from_dict(data)

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
    def test_division_by_zero_raises(self):
        for expression in ("1 / 0", "1 // 0", "1 % 0", "attacker.balance / vault.balance"):
            with self.subTest(expression=expression), self.assertRaises(ZeroDivisionError):
                safe_eval(expression, {"attacker": {"balance": 1}, "vault": {"balance": 0}})

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


class TestCompilerValidation(unittest.TestCase):
    def test_invalid_fork_urls_rejected(self):
        for url in ('https://example/\nattack', 'https://example/\rattack',
                    'https://example/"attack', "https://example/'attack",
                    "ftp://example/rpc", "https:///rpc", "https://example:bad/rpc",
                    "https://[bad/rpc", "https://example/\\attack"):
            with self.subTest(url=url), self.assertRaises(ShadowStrikeValidationError):
                scenario = _make_scenario()
                scenario.initial_state.fork_url = url
                ScenarioCompiler().compile(scenario)

    def test_raw_code_fields_are_rejected(self):
        for field, payload in (("scenario_id", "x\ncontract Injected {}"),
                               ("caller", "address(0)); revert(); //"),
                               ("function", "deposit; revert()"),
                               ("target", "vault; revert()")):
            with self.subTest(field=field), self.assertRaises(ShadowStrikeValidationError):
                scenario = _make_scenario()
                scenario.initial_state.target_contracts = {"vault": "0x" + "1" * 40}
                setattr(scenario if field == "scenario_id" else scenario.steps[0], field, payload)
                ScenarioCompiler().compile(scenario)


class TestCompiler(unittest.TestCase):
    def setUp(self):
        forge = shutil.which("forge") or str(Path.home() / ".foundry/bin/forge")
        if not Path(forge).is_file():
            self.skipTest("Foundry is required for Solidity compilation regression tests")
        solc_override = os.environ.get("FOUNDRY_SOLC")
        solc = Path(solc_override) if solc_override else Path.home() / ".svm/0.8.19/solc-0.8.19"
        if not solc.is_file() or not os.access(solc, os.X_OK):
            self.skipTest("Solc 0.8.19 is required for offline Solidity compilation regression tests")
        repo = Path(__file__).resolve().parents[1]
        if not (repo / "lib").is_dir() and "forge-std" not in os.environ.get("FOUNDRY_REMAPPINGS", ""):
            self.skipTest("forge-std is required for Solidity compilation regression tests")
        self.forge = forge
        environment = patch.dict(os.environ, {
            "PATH": str(Path(forge).parent) + os.pathsep + os.environ["PATH"],
        })
        environment.start()
        self.addCleanup(environment.stop)
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        shutil.copytree(repo / "contracts/src", self.root / "contracts/src")
        shutil.copy(repo / "foundry.toml", self.root / "foundry.toml")
        # Use a standard local installation when present. FOUNDRY_REMAPPINGS
        # and FOUNDRY_SOLC can also point at externally provisioned dependencies.
        if (repo / "lib").is_dir():
            (self.root / "lib").symlink_to(repo / "lib", target_is_directory=True)

    def assert_forge_builds(self, test_path):
        result = subprocess.run(
            [self.forge, "build", str(test_path.relative_to(self.root)), "--root", str(self.root), "--offline"],
            capture_output=True, text=True, timeout=120, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.root / "out" / test_path.name).is_dir())

    def test_compiles_to_nonempty_solidity(self):
        s = _make_scenario(initial_state=InitialState(
            fork_url="https://example/rpc", fork_block=1,
            target_contracts={"vault": "0x1111111111111111111111111111111111111111"},
        ))
        compiler = ScenarioCompiler(target_types={"vault": "IVault"})
        for fork_url in ("https://example/rpc", ""):
            with self.subTest(fork_url=fork_url):
                s.initial_state.fork_url = fork_url
                test_path = compiler.compile_to_file(
                    s, self.root / "contracts/test/generated",
                    attacker_contract_name="MaliciousReceiver_demo",
                )
                source = test_path.read_text()
                self.assertIn("pragma solidity", source)
                self.assertIn(s.scenario_id, source)
                self.assertEqual("vm.createSelectFork" in source, bool(fork_url))
                self.assert_forge_builds(test_path)

    def test_injection_payloads_are_data_and_generated_file_compiles(self):
        malicious_url = 'https://example/rpc"); revert("URL_INJECTED"); //'
        scenario = _make_scenario(
            hypothesis="hypothesis\r\n*/ revert(\"HYPOTHESIS_INJECTED\"); /*",
            initial_state=InitialState(
                fork_url=malicious_url, fork_block=1,
                target_contracts={"vault": "0x1111111111111111111111111111111111111111"},
            ),
            steps=[TransactionStep(
                step_id=1, caller="0x2222222222222222222222222222222222222222",
                target="vault", function="submit(string)",
                args=['sig-1', '"); revert("ARG_INJECTED"); //\\\n\r\t雪'],
                comment='comment\r\n*/ revert("COMMENT_INJECTED"); /*\u2028tail',
            )],
        )
        scenario.steps[0].function = "submit(string,string)"
        interface = self.root / "contracts/src/interfaces/IStringSink.sol"
        interface.write_text(
            "pragma solidity ^0.8.19; interface IStringSink { "
            "function submit(string calldata, string calldata) external; }"
        )
        compiler = ScenarioCompiler(target_types={"vault": "IStringSink"})
        output = self.root / "contracts/test/generated"
        with self.assertRaises(ShadowStrikeValidationError):
            compiler.compile_to_file(scenario, output)
        self.assertFalse(output.exists(), "Invalid URLs must not produce a file")
        # Reject the hostile URL, then build the same hostile prose/arguments
        # with a valid URL. forge build compiles only; it never contacts this URL.
        scenario.initial_state.fork_url = "https://example.invalid/rpc?key=value&other=1"
        path = compiler.compile_to_file(scenario, output)
        source = path.read_text()
        self.assertIn('vault.submit("sig-1", "\\x22); revert(\\x22ARG_INJECTED', source)
        self.assertNotIn('revert("ARG_INJECTED")', source)
        self.assertNotIn("URL_INJECTED", source)
        self.assertNotIn("*/", source)
        self.assertNotIn("/*", source)
        for line in source.splitlines():
            if "COMMENT_INJECTED" in line or "HYPOTHESIS_INJECTED" in line:
                self.assertTrue(line.lstrip().startswith("//"), line)
        self.assert_forge_builds(path)

    def test_cmd_run_scenario_attack_compiles_before_execution(self):
        from shadow_strike.cli import cmd_run_scenario

        s = _make_scenario(initial_state=InitialState(
            fork_url="", fork_block=0,
            target_contracts={"vault": "0x1111111111111111111111111111111111111111"},
        ))
        scenario_path = self.root / "scenario.yaml"
        save_scenario_yaml(s, scenario_path)

        class CompileOnlyBoundary(Exception):
            """Stop the CLI before any scenario is executed or stored."""

        def compile_only(scenario, test_path):
            self.assertEqual(scenario.scenario_id, s.scenario_id)
            source = test_path.read_text()
            self.assertIn("MaliciousReceiver_demo attacker;", source)
            self.assertIn("attacker.attack();", source)
            self.assertNotIn("vm.createSelectFork", source)
            self.assert_forge_builds(test_path)
            raise CompileOnlyBoundary

        with (
            patch("shadow_strike.execution.foundry_runner.ForgeRunner.run", side_effect=compile_only) as run,
            self.assertRaises(CompileOnlyBoundary),
        ):
            cmd_run_scenario(Namespace(file=scenario_path, engine="foundry", foundry_root=str(self.root)))
        run.assert_called_once()


class TestVerifierEvaluationErrors(unittest.TestCase):
    def test_evaluation_errors_fail_only_the_affected_condition(self):
        for expression, message in (
            ("1/0", "division by zero"),
            ('"a" - 1', "unsupported operand type"),
            ("missing > 0", "unknown identifier: 'missing'"),
        ):
            with self.subTest(expression=expression):
                scenario = _make_scenario(success_conditions=[
                    SuccessCondition(expression=expression, description="malformed"),
                    SuccessCondition(expression="balance == 1", description="valid"),
                ])
                result = ExecutionResult(scenario.scenario_id, False, None, {"balance": 1}, {}, [])

                verdict = Verifier().verify(scenario, result)

                self.assertFalse(verdict.verified)
                self.assertEqual(verdict.verdict, "error")
                failed, valid = verdict.condition_results
                self.assertFalse(failed["passed"])
                self.assertIn(message, failed["error"])
                self.assertTrue(valid["passed"])
                self.assertIsNone(valid["error"])
                self.assertEqual(verdict.proof_artifact["condition_results"], verdict.condition_results)

    def test_invariant_evaluation_error_is_informational(self):
        scenario = _make_scenario(
            success_conditions=[SuccessCondition(expression="balance == 1", description="valid")],
            invariants_under_test=["1/0"],
        )
        result = ExecutionResult(scenario.scenario_id, False, None, {"balance": 1}, {}, [])

        verdict = Verifier().verify(scenario, result)

        self.assertTrue(verdict.verified)
        self.assertEqual(verdict.invariant_violations, ["1/0  (unevaluable: division by zero)"])


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
        self.assertFalse(result.reverted, result.revert_reason)
        self.assertTrue(result.state_vars)
        self.assertEqual(verdict.verdict, "resisted")
        self.assertTrue(verdict.condition_results)
        self.assertTrue(all(c["error"] is None for c in verdict.condition_results))
        self.assertLessEqual(result.state_vars["attacker"]["eth_balance_after"], result.state_vars["attacker"]["eth_balance_before"])

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
