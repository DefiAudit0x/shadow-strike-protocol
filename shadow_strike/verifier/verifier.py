"""
shadow_strike.verifier.verifier
=================================
Deterministic verdict layer. No LLM call happens anywhere in this file
— that is the whole point (architecture §2.4 / §0 principle #2).
"""

from __future__ import annotations

from shadow_strike.core.models import AttackScenario, ExecutionResult, VerificationResult
from shadow_strike.core.safe_eval import safe_eval, UnsafeExpressionError


class Verifier:
    def verify(self, scenario: AttackScenario, execution_result: ExecutionResult) -> VerificationResult:
        condition_results = []
        for cond in scenario.success_conditions:
            try:
                passed = bool(safe_eval(cond.expression, execution_result.state_vars))
                error = None
            except UnsafeExpressionError as e:
                # A condition that fails safety review NEVER silently
                # counts as passed — it's recorded as a hard failure of
                # that condition, visible in the proof artifact.
                passed = False
                error = str(e)
            condition_results.append({
                "expression": cond.expression,
                "description": cond.description,
                "passed": passed,
                "error": error,
            })

        invariant_violations = []
        for inv in scenario.invariants_under_test:
            try:
                holds = bool(safe_eval(inv, execution_result.state_vars))
            except UnsafeExpressionError as e:
                holds = False
                invariant_violations.append(f"{inv}  (unevaluable: {e})")
                continue
            if not holds:
                invariant_violations.append(inv)

        verified = (
            not execution_result.reverted
            and all(c["passed"] for c in condition_results)
            and len(condition_results) > 0
        )

        proof_artifact = {
            "scenario": scenario.to_dict(),
            "engine": execution_result.engine,
            "reverted": execution_result.reverted,
            "revert_reason": execution_result.revert_reason,
            "state_vars": execution_result.state_vars,
            "state_diff": execution_result.state_diff,
            "call_trace": execution_result.call_trace,
            "condition_results": condition_results,
            "invariant_violations": invariant_violations,
        }

        return VerificationResult(
            scenario_id=scenario.scenario_id,
            verified=verified,
            condition_results=condition_results,
            invariant_violations=invariant_violations,
            proof_artifact=proof_artifact,
        )
