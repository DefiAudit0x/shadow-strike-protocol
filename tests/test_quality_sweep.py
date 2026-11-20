"""Part 20 regressions for documentation-adjacent robustness and reporting."""
from __future__ import annotations

import copy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import yaml

from shadow_strike.agent.nodes import hypothesis_node
from shadow_strike.attack_library.registry import AttackLibrary
from shadow_strike.core.models import AttackScenario, ExecutionResult, ShadowStrikeValidationError
from shadow_strike.core.safe_eval import UnsafeExpressionError, safe_eval
from shadow_strike.core.scenario_loader import ScenarioFileError, load_scenario_yaml, save_scenario_yaml
from shadow_strike.core.severity import SEVERITY_BY_CLASS
from shadow_strike.execution.mock_executor import Ledger, MockExecutor, MockWorld, SimplePool
from shadow_strike.reporting.report_generator import (
    _recommendation_for,
    generate_finding_markdown,
    generate_summary_report,
)
from shadow_strike.storage.db import KnowledgeStore
from shadow_strike.verifier.verifier import Verifier

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / 'examples/historical_incidents/the_dao_2016_reentrancy.yaml'


class TestQualitySweep(unittest.TestCase):
    def proof(self):
        scenario = load_scenario_yaml(SCENARIO)
        result = MockExecutor(contract_kinds={
            'vault': 'VulnerableVault', 'attacker': 'ReentrantAttacker',
        }).execute(scenario)
        verdict = Verifier().verify(scenario, result)
        self.assertTrue(verdict.verified)
        return verdict.proof_artifact

    def test_private_identifiers_and_attributes_are_blocked(self):
        for base in ({'_secret': 7}, SimpleNamespace(_secret=7)):
            for expression in ('value._secret', 'value.__class__', 'value.__dict__'):
                with self.subTest(expression=expression, base=type(base)), self.assertRaises(UnsafeExpressionError):
                    safe_eval(expression, {'value': base})
        with self.assertRaises(UnsafeExpressionError):
            safe_eval('_secret', {'_secret': 7})
        self.assertEqual(safe_eval('value.balance + 2', {'value': {'balance': 3}}), 5)

    def test_safe_eval_c06_never_invokes_properties_or_object_operators(self):
        class Object:
            calls = 0

            @property
            def balance(self):
                self.calls += 1
                return 1

            def __bool__(self):
                self.calls += 1
                return True

        obj = Object()
        for expression in ('value.balance', 'not value', 'value == 1', 'value + 1'):
            with self.subTest(expression=expression), self.assertRaises(UnsafeExpressionError):
                safe_eval(expression, {'value': obj})
        self.assertEqual(obj.calls, 0)
        with self.assertRaises(UnsafeExpressionError):
            safe_eval('value()', {'value': lambda: 1})

    def test_safe_eval_c07_flat_dotted_context(self):
        self.assertEqual(safe_eval('a.b', {'a.b': 1}), 1)
        self.assertEqual(safe_eval('a.b.c', {'a': {'b.c': 2}}), 2)
        self.assertEqual(safe_eval('a.b', {'a': {'b': 3}}), 3)
        with self.assertRaises(UnsafeExpressionError):
            safe_eval('a._b', {'a._b': 1})

    def test_safe_eval_c08_short_circuit(self):
        for expression, expected in (
            ('True or 1/0', True), ('False and missing.value', False),
            ('3 < 2 < missing', False), ('1 < 2 < 3', True),
            ('False or True', True), ('True and False', False),
        ):
            with self.subTest(expression=expression):
                self.assertIs(safe_eval(expression, {}), expected)

    def test_safe_eval_c09_resource_limits(self):
        expressions = (
            "'x' * 1000000", "1000000 * 'x'", "('x' * 40000) + ('x' * 40000)",
            '(((2 ** 12) ** 12) ** 12) ** 12',
            '1' + ' ' * 8192, '-' * 70 + '1',
            ' or '.join(['0'] * 1100), "'%1000000000s' % 'x'",
        )
        for expression in expressions:
            with self.subTest(expression=expression[:80]), self.assertRaises(UnsafeExpressionError):
                safe_eval(expression, {})
        self.assertEqual(safe_eval("'x' * 10", {}), 'x' * 10)
        self.assertEqual(safe_eval('(2 ** 12) ** 2', {}), 2 ** 24)
        for value in ('x' * 65537, 1 << 4096):
            with self.assertRaises(UnsafeExpressionError):
                safe_eval('value', {'value': value})

    def test_loader_rejects_unknown_keys_and_preserves_reentry_setting(self):
        scenario = load_scenario_yaml(SCENARIO)
        scenario.attacker_max_reentries = 7
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'scenario.yaml'
            save_scenario_yaml(scenario, path)
            self.assertEqual(load_scenario_yaml(path).to_dict(), scenario.to_dict())
            data = scenario.to_dict()
            data['max_retires'] = 9
            path.write_text(yaml.safe_dump(data))
            with self.assertRaisesRegex(ScenarioFileError, 'unknown top-level.*max_retires'):
                load_scenario_yaml(path)

    def test_missing_attacker_raises_validation_error(self):
        data = load_scenario_yaml(SCENARIO).to_dict()
        del data['attacker']
        with self.assertRaisesRegex(ShadowStrikeValidationError, 'attacker'):
            AttackScenario.from_dict(data)

    def test_save_missing_scenario_is_clean_cli_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'out.yaml'
            result = subprocess.run([
                sys.executable, '-m', 'shadow_strike.cli', 'save-scenario', 'missing',
                '--db', str(Path(tmp) / 'store.sqlite3'), '--out', str(out),
            ], check=False, cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('ERROR: scenario not found: missing', result.stderr)
            self.assertNotIn('Traceback', result.stderr)
            self.assertFalse(out.exists())

    def test_save_scenario_without_attempts_succeeds(self):
        scenario = load_scenario_yaml(SCENARIO)
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / 'store.sqlite3')
            store = KnowledgeStore(db)
            store.save_scenario(scenario)
            store.close()
            out = Path(tmp) / 'out.yaml'
            result = subprocess.run([
                sys.executable, '-m', 'shadow_strike.cli', 'save-scenario', scenario.scenario_id,
                '--db', db, '--out', str(out),
            ], check=False, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(load_scenario_yaml(out).to_dict(), scenario.to_dict())

    def test_defensive_modifiers_do_not_trigger_heuristic_hypotheses(self):
        state = hypothesis_node({'target_contract_source': 'onlyOwner _disableInitializers'}, library=AttackLibrary())
        self.assertFalse(state['hypotheses'])

    def test_cross_contract_patterns_cover_calls_and_callbacks(self):
        for source in ('target.staticcall(data)', 'target.delegatecall(data)',
                       'function onERC721Received('):
            state = hypothesis_node({'target_contract_source': source}, library=AttackLibrary())
            self.assertIn('cross_contract', [h['vulnerability_class'] for h in state['hypotheses']])

    def test_spot_price_is_units_of_a_per_b_and_rises_when_buying_b(self):
        pool = SimplePool('pool', reserve_a=80, reserve_b=40)
        self.assertEqual(pool.spot_price(), 2)
        world = MockWorld(ledger=Ledger({'attacker': 80, 'pool': 80}),
                          token_b_ledger=Ledger({'pool': 40}))
        pool.swapAForB('attacker', world, amount_a=80)
        self.assertEqual(pool.spot_price(), 8)

    def test_all_classes_have_specific_recommendations_and_shared_severity(self):
        from shadow_strike.integrations import axiom_adapter
        from shadow_strike.reporting import report_generator
        self.assertEqual(set(SEVERITY_BY_CLASS), set(AttackLibrary().available_classes()))
        self.assertIs(axiom_adapter.SEVERITY_BY_CLASS, SEVERITY_BY_CLASS)
        self.assertIs(report_generator.SEVERITY_BY_CLASS, SEVERITY_BY_CLASS)
        for cls in AttackLibrary().available_classes():
            self.assertNotEqual(_recommendation_for(cls), _recommendation_for('unknown'))

    def test_only_foundry_gets_real_evm_note(self):
        proof = self.proof()
        for engine in ('mock', 'unknown', 'custom', None, 'foundry'):
            proof['engine'] = engine
            report = generate_finding_markdown(proof)
            self.assertEqual('✅ executed via' in report, engine == 'foundry')
            self.assertEqual('real-EVM execution is unverified' in report,
                             engine not in ('mock', 'foundry'))
        self.assertNotIn('gas_used', proof)
        self.assertNotIn('gas_used', ExecutionResult.__dataclass_fields__)
        self.assertNotIn('gas_used', report)

    def test_summary_requires_verified_evidence(self):
        proof = self.proof()
        self.assertIn('**Findings:** 1', generate_summary_report([proof], 'test'))
        for field, value in (('verdict', 'resisted'), ('verdict', 'error'),
                             ('reverted', True), ('condition_results', []), ('state_vars', {})):
            invalid = copy.deepcopy(proof)
            invalid[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                generate_summary_report([proof, invalid], 'test')
            self.assertIn('NOT VERIFIED', generate_finding_markdown(invalid))
        for key, value in (('passed', False), ('error', 'evaluation failed')):
            invalid = copy.deepcopy(proof)
            invalid['condition_results'][0][key] = value
            with self.assertRaises(ValueError):
                generate_summary_report([invalid], 'test')
        invalid = copy.deepcopy(proof)
        del invalid['verdict']
        with self.assertRaises(ValueError):
            generate_summary_report([invalid], 'test')
        self.assertIn('**Findings:** 0', generate_summary_report([], 'test'))


if __name__ == '__main__':
    unittest.main()
