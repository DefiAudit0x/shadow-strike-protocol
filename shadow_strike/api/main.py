"""
shadow_strike.api.main
========================
Orchestration API. Requires: pip install fastapi uvicorn

Run: uvicorn shadow_strike.api.main:app --reload

This is intentionally thin — it exists to expose the same
SimpleShadowStrikeGraph / KnowledgeStore used by the CLI over HTTP +
WebSocket, for a dashboard or CI integration. Not required to use
Shadow Strike at all (the CLI and examples/run_demo.py need nothing
beyond the stdlib + jinja2 + pyyaml).
"""

from __future__ import annotations

from typing import Literal

try:
    from fastapi import FastAPI, WebSocket
    from pydantic import BaseModel
except ImportError as e:
    raise ImportError(
        "shadow_strike.api requires: pip install fastapi uvicorn pydantic. "
        "The core engine (shadow_strike.cli, examples/run_demo.py) does not."
    ) from e

from shadow_strike.agent.graph_simple import SimpleShadowStrikeGraph
from shadow_strike.agent.llm_providers import build_llm_fn
from shadow_strike.attack_library.registry import AttackLibrary
from shadow_strike.benchmark.runner import run_benchmark
from shadow_strike.execution.mock_executor import MockExecutor
from shadow_strike.integrations.axiom_adapter import SentinelHypothesisRequest, handle_sentinel_request
from shadow_strike.storage.db import KnowledgeStore
from shadow_strike.verifier.verifier import Verifier

app = FastAPI(title="Shadow Strike Protocol API")
store = KnowledgeStore(db_path="shadow_strike_knowledge.sqlite3")
library = AttackLibrary()


class RunRequest(BaseModel):
    source_code: str
    protocol_name: str
    target_contracts: dict[str, str]
    fork_url: str = ""
    fork_block: int = 0
    attacker_initial_eth: float = 1.0
    engine: str = "mock"   # "mock" | "foundry"
    max_retries: int = 3
    # Part 10: LLM provider for hypothesis generation ("echo" is the
    # offline test double; "anthropic" reads its key from the server env).
    # None means heuristics only.
    llm: Literal["anthropic", "echo"] | None = None


@app.get("/attack-library")
def list_attack_library():
    return [library.get(vc) for vc in library.available_classes()]


@app.get("/attack-library/{vulnerability_class}")
def get_attack_library_entries(vulnerability_class: str):
    rows = store.library_entries(vulnerability_class)
    return [dict(r) for r in rows]


@app.post("/runs")
def create_run(req: RunRequest):
    if req.engine == "foundry":
        from shadow_strike.execution.foundry_runner import ForgeRunner
        executor = ForgeRunner(foundry_project_root=".")
    else:
        kinds = {next(iter(req.target_contracts)): "VulnerableVault", "attacker": "ReentrantAttacker"}
        executor = MockExecutor(contract_kinds=kinds)

    graph = SimpleShadowStrikeGraph(
        executor=executor, verifier=Verifier(), library=library, max_retries=req.max_retries,
        llm_fn=build_llm_fn(req.llm),
    )
    result = graph.run(
        target_contract_source=req.source_code,
        target_protocol_name=req.protocol_name,
        fork_url=req.fork_url,
        fork_block=req.fork_block,
        target_contracts=req.target_contracts,
        attacker_initial_eth=req.attacker_initial_eth,
    )

    scenario = result.get("current_scenario")
    if scenario is not None:
        # Sync endpoints run in a worker thread; the module-level SQLite
        # connection belongs to the importing thread, so use a local one.
        run_store = KnowledgeStore(db_path=store.db_path)
        try:
            run_store.save_scenario(scenario)
        finally:
            run_store.close()

    return {
        "scenario_id": scenario.scenario_id if scenario else None,
        "stopped_reason": result["stopped_reason"],
        "verified": bool(result["final_proof"]),
        "proof": result["final_proof"],
        "history": result["history"],
    }


@app.get("/runs/{scenario_id}")
def get_run(scenario_id: str):
    rows = store.attempts_for_scenario(scenario_id)
    return [dict(r) for r in rows]


def _build_mock_executors(executor_config: dict[str, dict]) -> dict[str, MockExecutor]:
    """executor_config: {vulnerability_class: {"contract_kinds": {...}, "contract_params": {...}}}
    — the caller decides which mock contracts model each class, since
    that's inherently scenario-shape-specific (see benchmark.runner's
    own docstring: one generic mock world can't cover every class)."""
    out = {}
    for vuln_class, cfg in executor_config.items():
        out[vuln_class] = MockExecutor(
            contract_kinds=cfg.get("contract_kinds", {}),
            contract_params=cfg.get("contract_params", {}),
        )
    return out


class BenchmarkRequest(BaseModel):
    source_code: str
    protocol_name: str
    target_contracts: dict[str, str]
    executor_config: dict[str, dict] = {}   # see _build_mock_executors
    attacker_initial_eth: float = 1.0
    fork_url: str = ""
    fork_block: int = 0


@app.post("/benchmark")
def create_benchmark(req: BenchmarkRequest):
    """Idea #4: score a contract against every Attack Library class the
    heuristics flag as plausible, independently. See
    shadow_strike.benchmark.runner for the full scorecard semantics."""
    executors = _build_mock_executors(req.executor_config)
    report = run_benchmark(
        target_contract_source=req.source_code,
        target_protocol_name=req.protocol_name,
        target_contracts=req.target_contracts,
        executors=executors,
        fork_url=req.fork_url, fork_block=req.fork_block,
        attacker_initial_eth=req.attacker_initial_eth, library=library,
    )
    return {
        "target_protocol": report.target_protocol,
        "hypotheses_flagged": report.hypotheses_flagged,
        "results": [
            {
                "vulnerability_class": r.vulnerability_class, "status": r.status,
                "scenario_id": r.scenario_id, "detail": r.detail,
                "proof_artifact": r.proof_artifact,
            } for r in report.results
        ],
        "scorecard_text": report.scorecard(),
    }


class SentinelRequest(BaseModel):
    """Idea #2: the Axiom/Sentinel integration boundary, over HTTP —
    the same contract as integrations.axiom_adapter.handle_sentinel_request,
    for when Axiom and Shadow Strike run as separate services rather
    than sharing a Python runtime."""
    request_id: str
    target_protocol: str
    source_code: str
    target_contracts: dict[str, str]
    suspected_vulnerability_class: str | None = None
    executor_config: dict[str, dict] = {}
    attacker_initial_eth: float = 1.0
    fork_url: str = ""
    fork_block: int = 0


@app.post("/sentinel/hypothesis")
def sentinel_hypothesis(req: SentinelRequest):
    executors = _build_mock_executors(req.executor_config)
    sentinel_req = SentinelHypothesisRequest(
        request_id=req.request_id, target_protocol=req.target_protocol, source_code=req.source_code,
        target_contracts=req.target_contracts, suspected_vulnerability_class=req.suspected_vulnerability_class,
        attacker_initial_eth=req.attacker_initial_eth, fork_url=req.fork_url, fork_block=req.fork_block,
    )
    resp = handle_sentinel_request(sentinel_req, executors, library)
    return {
        "request_id": resp.request_id, "verified": resp.verified, "severity": resp.severity,
        "scenario_id": resp.scenario_id, "tested_classes": resp.tested_classes,
        "recommendation": resp.recommendation, "proof_artifact": resp.proof_artifact,
    }


@app.websocket("/runs/{scenario_id}/stream")
async def stream_run(websocket: WebSocket, scenario_id: str):
    """Live node-by-node progress, for a dashboard — mirrors the
    `on_step` callback SimpleShadowStrikeGraph.run() already accepts."""
    await websocket.accept()
    await websocket.send_json({"info": "streaming not yet wired to a background job queue — see roadmap §Phase 2"})
    await websocket.close()
