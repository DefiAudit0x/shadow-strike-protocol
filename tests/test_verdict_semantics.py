"""Part 12: failures and missing evidence never establish resistance."""
import unittest
from unittest.mock import patch

from test_benchmark import MULTI_VULN_SOURCE
from test_pipeline import _make_scenario

from shadow_strike.benchmark.runner import BenchmarkReport, ClassResult, run_benchmark
from shadow_strike.core.models import AttackScenario, ExecutionResult, SuccessCondition
from shadow_strike.execution.mock_executor import MockExecutor
from shadow_strike.integrations.axiom_adapter import SentinelHypothesisRequest, handle_sentinel_request
from shadow_strike.reporting.report_generator import generate_finding_markdown
from shadow_strike.verifier.verifier import Verifier


class TestVerdictSemantics(unittest.TestCase):
    def test_execution_evidence_must_match_scenario_id(self):
        scenario = _make_scenario()
        scenario.success_conditions = [SuccessCondition('x == 1', 'x must equal one')]
        unrelated = ExecutionResult(
            scenario_id='UNRELATED', reverted=False, revert_reason=None,
            state_vars={'x': 1}, state_diff={}, call_trace=[], engine='mock',
        )

        mismatch = Verifier().verify(scenario, unrelated)
        self.assertFalse(mismatch.verified)
        self.assertEqual(mismatch.verdict, 'error')
        self.assertIn('scenario_id mismatch', mismatch.proof_artifact['error'])
        self.assertIn('scenario_id mismatch', mismatch.condition_results[0]['error'])
        self.assertNotIn('state_vars', mismatch.proof_artifact)

        matching = ExecutionResult(
            scenario_id=scenario.scenario_id, reverted=False, revert_reason=None,
            state_vars={'x': 1}, state_diff={}, call_trace=[], engine='mock',
        )
        self.assertTrue(Verifier().verify(scenario, matching).verified)

    def test_zero_tested_has_no_ratio(self):
        for rows in ([], [ClassResult('reentrancy', 'no_executor')],
                     [ClassResult('reentrancy', 'build_error')]):
            card = BenchmarkReport('test', [], rows).scorecard()
            self.assertIn('INCONCLUSIVE', card)
            self.assertNotIn('0/0', card)
            self.assertNotIn('tested classes exploitable', card)

    def test_planner_error_is_error_not_resisted(self):
        with patch.dict('shadow_strike.benchmark.runner.SCENARIO_BUILDERS',
                        {'reentrancy': unittest.mock.Mock(side_effect=ValueError('planner failed'))}):
            report = run_benchmark(MULTI_VULN_SOURCE, 'test', {'vault': '0xabc'}, {}, db_path=':memory:')
            row = next(r for r in report.results if r.vulnerability_class == 'reentrancy')
            self.assertEqual(row.verdict, 'error')
            self.assertNotEqual(row.status, 'resisted')
            req = SentinelHypothesisRequest('r', 'test', MULTI_VULN_SOURCE, {'vault': '0xabc'}, 'reentrancy')
            response = handle_sentinel_request(req, {}, db_path=':memory:')
            self.assertEqual(response.verdict, 'error')
            self.assertEqual(response.tested_classes[0]['status'], 'error')

    def test_invariants_are_informational_and_reported(self):
        executor = MockExecutor(contract_kinds={'vault': 'VulnerableVault', 'attacker': 'ReentrantAttacker'})
        report = run_benchmark(MULTI_VULN_SOURCE, 'test', {'vault': '0xabc'},
                               {'reentrancy': executor}, db_path=':memory:')
        row = next(r for r in report.results if r.vulnerability_class == 'reentrancy')
        self.assertEqual(row.verdict, 'verified')
        scenario = AttackScenario.from_dict(row.proof_artifact['scenario'])
        scenario.invariants_under_test = ['1 == 0']
        execution = executor.execute(scenario)
        verdict = Verifier().verify(scenario, execution)
        self.assertTrue(verdict.verified)
        self.assertEqual(verdict.invariant_violations, ['1 == 0'])
        self.assertEqual(verdict.proof_artifact['invariants_policy'], 'informational')
        self.assertIn('informational; do not affect the verdict', generate_finding_markdown(verdict.proof_artifact))
        for reverted, expected in ((True, 'error'), (False, 'inconclusive')):
            result = ExecutionResult(scenario.scenario_id, reverted, 'compile failure', {}, {}, [])
            self.assertEqual(Verifier().verify(scenario, result).verdict, expected)
        scenario.success_conditions[0].expression = '1 == 0'
        self.assertEqual(Verifier().verify(scenario, execution).verdict, 'resisted')

    def test_harness_exception_is_error(self):
        executor = unittest.mock.Mock()
        executor.execute.side_effect = RuntimeError('harness failed')
        report = run_benchmark(MULTI_VULN_SOURCE, 'test', {'vault': '0xabc'},
                               {'reentrancy': executor}, db_path=':memory:')
        self.assertEqual(next(r for r in report.results if r.vulnerability_class == 'reentrancy').verdict, 'error')
