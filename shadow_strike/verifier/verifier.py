"""
shadow_strike.verifier.verifier
=================================
Deterministic verdict layer. No LLM call happens anywhere in this file
— that is the whole point (architecture §2.4 / §0 principle #2).
"""

from __future__ import annotations

from shadow_strike.core.models import AttackScenario, ExecutionResult, VerificationResult
from shadow_strike.core.safe_eval import safe_eval


class Verifier:
    def verify(self, scenario: AttackScenario, execution_result: ExecutionResult) -> VerificationResult:
        if execution_result.scenario_id != scenario.scenario_id:
            mismatch_reason = (
                f"scenario_id mismatch: expected {scenario.scenario_id!r}, "
                f"got {execution_result.scenario_id!r}"
            )
            condition_results = [{
                "expression": cond.expression,
                "description": cond.description,
                "passed": False,
                "error": mismatch_reason,
            } for cond in scenario.success_conditions]
            proof_artifact = {
                "verdict": "error",
                "error": mismatch_reason,
                "scenario": scenario.to_dict(),
                "execution_scenario_id": execution_result.scenario_id,
                "engine": execution_result.engine,
            }
            return VerificationResult(
                scenario_id=scenario.scenario_id,
                verified=False,
                verdict="error",
                condition_results=condition_results,
                invariant_violations=[],
                proof_artifact=proof_artifact,
            )

        condition_results = []
        for cond in scenario.success_conditions:
            try:
                passed = bool(safe_eval(cond.expression, execution_result.state_vars))
                error = None
            except Exception as e:  # noqa: BLE001 - Record any evaluation failure on this condition.
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
            except Exception as e:  # noqa: BLE001 - Invariant evaluation is informational.
                invariant_violations.append(f"{inv}  (unevaluable: {e})")
                continue
            if not holds:
                invariant_violations.append(inv)

        verified = (
            not execution_result.reverted
            and all(c["passed"] for c in condition_results)
            and len(condition_results) > 0
        )

        # A missing post-state cannot establish resistance (e.g. forge build failure).
        if not execution_result.state_vars:
            verdict = "error" if execution_result.reverted else "inconclusive"
        elif any(c["error"] is not None for c in condition_results):
            verdict = "error"
        elif not condition_results:
            verdict = "inconclusive"
        else:
            verdict = "verified" if verified else "resisted"
        verified = verdict == "verified"

        proof_artifact = {
            "verdict": verdict,
            "invariants_policy": "informational",
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
            verdict=verdict,
            condition_results=condition_results,
            invariant_violations=invariant_violations,
            proof_artifact=proof_artifact,
        )
