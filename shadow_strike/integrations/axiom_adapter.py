"""
shadow_strike.integrations.axiom_adapter
===========================================
Idea #2 from the roadmap discussion: Shadow Strike as the execution/
verification backend behind Axiom's Sentinel agent. Same philosophy as
the rest of this project — Sentinel (an LLM-driven agent) proposes a
hypothesis; this adapter is the boundary where "proposed" becomes
"proven or refuted" via the exact same AttackScenario -> executor ->
Verifier pipeline everything else in Shadow Strike uses. Sentinel never
gets to just assert a finding through this path.

Transport-agnostic by design: this is a plain Python call interface
(`handle_sentinel_request`), not an HTTP/queue client. Axiom's own
orchestration layer (Cue, per your architecture notes) decides how to
actually invoke this — in-process import if Axiom and Shadow Strike
share a runtime, or wrapped behind shadow_strike/api/main.py's FastAPI
layer if they're separate services. Both call the same function below;
only the transport differs.

NOT exercised against the real Axiom codebase (not available in this
environment) — tested here with a synthetic request matching the
shape Sentinel would plausibly send, against the existing mock
executors, proving the call contract itself works end to end.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from shadow_strike.agent.nodes import SCENARIO_BUILDERS, recon_node, hypothesis_node
from shadow_strike.attack_library.registry import AttackLibrary
from shadow_strike.benchmark.runner import run_benchmark, BenchmarkReport
from shadow_strike.verifier.verifier import Verifier

SEVERITY_BY_CLASS = {
    "reentrancy": "critical", "oracle_manipulation": "critical", "flash_loan": "critical",
    "price_manipulation": "critical", "access_control": "high", "signature_replay": "high",
    "initialization": "high", "upgradeability": "high", "accounting": "medium",
    "cross_contract": "medium", "economic": "medium",
}


@dataclass
class SentinelHypothesisRequest:
    """What Sentinel sends in. `suspected_vulnerability_class` is
    optional — give it when Sentinel's own reasoning already narrowed
    things down (cheaper, one scenario); omit it to run the full
    benchmark across every class the Attack Library's heuristics flag
    (more thorough, costs more executor time)."""
    request_id: str
    target_protocol: str
    source_code: str
    target_contracts: dict[str, str]
    suspected_vulnerability_class: str | None = None
    attacker_initial_eth: float = 1.0
    fork_url: str = ""
    fork_block: int = 0


@dataclass
class AxiomVerdictResponse:
    """What goes back to Sentinel. `verified=False` with
    `scenario_id=None` means "nothing in the Attack Library applied or
    was configured to run" — Sentinel should treat that as "Shadow
    Strike found nothing to test", NOT as "proven safe". Only a
    populated `tested_classes` list with explicit `resisted` entries
    supports a "we checked and it held" claim."""
    request_id: str
    verified: bool
    severity: str | None
    scenario_id: str | None
    tested_classes: list[dict]   # [{"vulnerability_class": ..., "status": ...}, ...]
    recommendation: str | None
    proof_artifact: dict | None = None


def handle_sentinel_request(
    request: SentinelHypothesisRequest,
    executors: dict[str, object],
    library: AttackLibrary | None = None,
) -> AxiomVerdictResponse:
    library = library or AttackLibrary()

    if request.suspected_vulnerability_class:
        return _handle_single_class(request, executors, library)
    return _handle_full_benchmark(request, executors, library)


def _handle_single_class(request: SentinelHypothesisRequest, executors, library) -> AxiomVerdictResponse:
    builder = SCENARIO_BUILDERS.get(request.suspected_vulnerability_class)
    if builder is None:
        return AxiomVerdictResponse(
            request_id=request.request_id, verified=False, severity=None, scenario_id=None,
            tested_classes=[{"vulnerability_class": request.suspected_vulnerability_class, "status": "no_builder"}],
            recommendation=f"no executable template for {request.suspected_vulnerability_class!r} yet — "
                            f"hand-author a scenario via core.scenario_loader instead",
        )

    state = {"target_contract_source": request.source_code, "target_protocol_name": request.target_protocol}
    state = recon_node(state)
    state = hypothesis_node(state, library=library)
    matching = [h for h in state["hypotheses"] if h["vulnerability_class"] == request.suspected_vulnerability_class]
    hypothesis = matching[0] if matching else {
        "vulnerability_class": request.suspected_vulnerability_class,
        "hypothesis": f"Sentinel-suspected {request.suspected_vulnerability_class} (no heuristic pattern matched locally)",
    }

    scenario = builder(
        hypothesis, request.target_contracts, request.attacker_initial_eth,
        request.fork_url, request.fork_block, library, request.target_protocol, state,
    )
    executor = executors.get(request.suspected_vulnerability_class)
    if executor is None:
        return AxiomVerdictResponse(
            request_id=request.request_id, verified=False, severity=None, scenario_id=scenario.scenario_id,
            tested_classes=[{"vulnerability_class": request.suspected_vulnerability_class, "status": "no_executor"}],
            recommendation="scenario built but no executor configured for this run — "
                            "nothing was actually executed, this is NOT a verdict",
        )

    result = executor.execute(scenario) if hasattr(executor, "execute") else executor.run(scenario)
    verdict = Verifier().verify(scenario, result)
    status = "exploitable" if verdict.verified else "resisted"

    return AxiomVerdictResponse(
        request_id=request.request_id,
        verified=verdict.verified,
        severity=SEVERITY_BY_CLASS.get(request.suspected_vulnerability_class) if verdict.verified else None,
        scenario_id=scenario.scenario_id,
        tested_classes=[{"vulnerability_class": request.suspected_vulnerability_class, "status": status}],
        recommendation=_recommendation(request.suspected_vulnerability_class) if verdict.verified else None,
        proof_artifact=verdict.proof_artifact if verdict.verified else None,
    )


def _handle_full_benchmark(request: SentinelHypothesisRequest, executors, library) -> AxiomVerdictResponse:
    report: BenchmarkReport = run_benchmark(
        target_contract_source=request.source_code,
        target_protocol_name=request.target_protocol,
        target_contracts=request.target_contracts,
        executors=executors,
        fork_url=request.fork_url, fork_block=request.fork_block,
        attacker_initial_eth=request.attacker_initial_eth, library=library,
    )
    exploitable = [r for r in report.results if r.status == "exploitable"]
    tested_classes = [{"vulnerability_class": r.vulnerability_class, "status": r.status} for r in report.results]

    if not exploitable:
        return AxiomVerdictResponse(
            request_id=request.request_id, verified=False, severity=None, scenario_id=None,
            tested_classes=tested_classes, recommendation=None,
        )

    # report the highest-severity exploitable finding as the headline
    # verdict; the full breakdown still travels in tested_classes
    worst = max(exploitable, key=lambda r: _severity_rank(SEVERITY_BY_CLASS.get(r.vulnerability_class, "medium")))
    return AxiomVerdictResponse(
        request_id=request.request_id, verified=True,
        severity=SEVERITY_BY_CLASS.get(worst.vulnerability_class),
        scenario_id=worst.scenario_id, tested_classes=tested_classes,
        recommendation=_recommendation(worst.vulnerability_class),
        proof_artifact=worst.proof_artifact,
    )


def _severity_rank(sev: str) -> int:
    return {"critical": 3, "high": 2, "medium": 1, "low": 0}.get(sev, 0)


def _recommendation(vuln_class: str) -> str:
    from shadow_strike.reporting.report_generator import _recommendation_for
    return _recommendation_for(vuln_class)
