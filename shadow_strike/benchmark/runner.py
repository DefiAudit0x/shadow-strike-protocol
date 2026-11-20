"""
shadow_strike.benchmark.runner
=================================
Idea #4 from the roadmap discussion: "does your contract survive the
Attack Library?" Unlike graph_simple.SimpleShadowStrikeGraph (which
commits to ONE hypothesis and retries it), the benchmark runner tries
EVERY vulnerability class the Attack Library's heuristics flag as
plausible, independently, and produces a scorecard — this is the
triage tool a bug-bounty platform or a protocol's CI pipeline would
actually want.

Each vulnerability class needs its own executor (a MockExecutor
configured with the right contract_kinds, or one shared ForgeRunner
for real-contract runs) — you can't model "all attack types" with one
generic mock world, since each targets a different contract shape.
Classes with no executor supplied are reported as SKIPPED, not FAILED
— skipped and "verified-not-exploitable" are different claims and the
scorecard keeps them visually distinct.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from shadow_strike.agent.nodes import SCENARIO_BUILDERS, hypothesis_node, recon_node
from shadow_strike.attack_library.registry import AttackLibrary
from shadow_strike.core.models import AttackScenario
from shadow_strike.execution.foundry_runner import execute_scenario
from shadow_strike.storage.persistence import run_store, save_run
from shadow_strike.verifier.verifier import Verifier


@dataclass
class ClassResult:
    vulnerability_class: str
    status: str   # "exploitable" | "resisted" | "no_builder" | "no_executor" | "build_error"
    scenario_id: str | None = None
    proof_artifact: dict | None = None
    detail: str | None = None


@dataclass
class BenchmarkReport:
    target_protocol: str
    hypotheses_flagged: list[str]
    results: list[ClassResult] = field(default_factory=list)

    def scorecard(self) -> str:
        lines = [f"Shadow Strike Benchmark — {self.target_protocol}", "=" * 50]
        icon = {
            "exploitable": "🔴 EXPLOITABLE",
            "resisted": "🟢 RESISTED",
            "no_builder": "⚪ NO BUILDER (roadmap class)",
            "no_executor": "⚪ SKIPPED (no executor configured)",
            "build_error": "🟡 BUILD ERROR",
        }
        for r in self.results:
            lines.append(f"{icon.get(r.status, r.status):32s} {r.vulnerability_class}"
                          + (f"  — {r.detail}" if r.detail else ""))
        exploitable = sum(1 for r in self.results if r.status == "exploitable")
        tested = sum(1 for r in self.results if r.status in ("exploitable", "resisted"))
        lines.append("-" * 50)
        lines.append(f"{exploitable}/{tested} tested classes exploitable"
                      + (f"  ({len(self.results) - tested} not tested)" if tested < len(self.results) else ""))
        return "\n".join(lines)


def run_benchmark(
    target_contract_source: str,
    target_protocol_name: str,
    target_contracts: dict[str, str],
    executors: dict[str, object],
    fork_url: str = "",
    fork_block: int = 0,
    attacker_initial_eth: float = 1.0,
    library: AttackLibrary | None = None,
    store=None,
    db_path: str = "shadow_strike_knowledge.sqlite3",
) -> BenchmarkReport:
    library = library or AttackLibrary()
    verifier = Verifier()

    state: dict = {"target_contract_source": target_contract_source}
    state = recon_node(state)
    state = hypothesis_node(state, library=library)

    flagged_classes = sorted({h["vulnerability_class"] for h in state["hypotheses"]})
    report = BenchmarkReport(target_protocol=target_protocol_name, hypotheses_flagged=flagged_classes)

    with run_store(store, db_path) as active_store:
        for vuln_class in flagged_classes:
            chosen = next(h for h in state["hypotheses"] if h["vulnerability_class"] == vuln_class)
            builder = SCENARIO_BUILDERS.get(vuln_class)

            if builder is None:
                report.results.append(ClassResult(vuln_class, "no_builder",
                                                    detail="see attack_library meta.yaml for why"))
                continue

            try:
                scenario: AttackScenario = builder(
                    chosen, target_contracts, attacker_initial_eth, fork_url, fork_block,
                    library, target_protocol_name, state,
                )
            except Exception as e:  # noqa: BLE001 — surfaced as a scorecard row, not a crash
                report.results.append(ClassResult(vuln_class, "build_error", detail=str(e)))
                continue

            executor = executors.get(vuln_class)
            if executor is None:
                report.results.append(ClassResult(vuln_class, "no_executor", scenario_id=scenario.scenario_id))
                continue

            result = execute_scenario(executor, scenario)
            verdict = verifier.verify(scenario, result)
            save_run(active_store, scenario, result, verdict,
                     failure_reason=result.revert_reason or "success conditions not met")

            report.results.append(ClassResult(
                vulnerability_class=vuln_class,
                status="exploitable" if verdict.verified else "resisted",
                scenario_id=scenario.scenario_id,
                proof_artifact=verdict.proof_artifact if verdict.verified else None,
                detail=None if verdict.verified else (result.revert_reason or "success conditions not met"),
            ))

    return report
