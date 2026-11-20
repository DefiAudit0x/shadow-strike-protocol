"""HTTP API for Shadow Strike.

Run with ``uvicorn shadow_strike.api.main:app``. Mutating requests require a
configured bearer token and return a job ID; clients poll ``GET /jobs/{job_id}``
for completion. SQLite storage is opened only when a request uses it.
"""

from __future__ import annotations

import hmac
import json
import math
import os
import re
import uuid
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from threading import Lock
from time import monotonic
from typing import Literal

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Request
    from fastapi.exceptions import RequestValidationError
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
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
from shadow_strike.storage.persistence import run_store, save_run
from shadow_strike.verifier.verifier import Verifier

API_TOKEN_ENV = "SHADOW_STRIKE_API_TOKEN"
DB_PATH_ENV = "SHADOW_STRIKE_DB_PATH"

app = FastAPI(title="Shadow Strike Protocol API")


def _sanitize_for_json(value):
    """Replace non-finite floats (NaN/Infinity) with strings so error
    details stay JSON-serializable. FastAPI's default validation-error
    handler can 500 on older FastAPI/Starlette releases when the detail
    carries a non-finite float (e.g. NaN rejected by allow_inf_nan=False),
    because Starlette serializes responses with allow_nan=False."""
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, dict):
        return {key: _sanitize_for_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize_for_json(item) for item in value]
    return value


@app.exception_handler(RequestValidationError)
async def _validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Same shape as FastAPI's default handler ({"detail": errors}, 422),
    # with non-finite floats sanitized so the response itself serializes.
    return JSONResponse(status_code=422, content={"detail": _sanitize_for_json(exc.errors())})


library = AttackLibrary()

# This queue is process-local. The bounded worker pool keeps requests from
# blocking while still limiting concurrent host executions.
_job_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="shadow-strike-api")
MAX_TRACKED_JOBS = 128
JOB_RETENTION_SECONDS = 3600


@dataclass
class _Job:
    future: Future
    completed_at: float | None = None


_jobs: dict[str, _Job] = {}
_jobs_lock = Lock()


def _redact_evidence(value):
    """Sanitize response copies, including legacy JSON stored as SQLite TEXT.

    RPC credentials can live in URL paths as well as userinfo/query strings, so
    suppress whole URLs even inside logs or other free-form evidence fields.
    """
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            name = re.sub(r"[^a-z0-9]", "", key.lower())
            # Singular AND plural suffixes: a prefixed plural such as
            # rpc_credentials normalizes to "rpccredentials", which matches
            # neither the singular suffix nor an exact "credentials" name.
            sensitive = name.endswith((
                "url", "urls", "password", "passwords", "secret", "secrets",
                "token", "tokens", "apikey", "apikeys", "credential", "credentials",
            ))
            result[key] = "[REDACTED]" if sensitive or name in {
                "authorization", "proxyauthorization", "credentials", "privatekey",
            } else _redact_evidence(item)
        return result
    if isinstance(value, (list, tuple)):
        return [_redact_evidence(item) for item in value]
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except (ValueError, RecursionError):
            decoded = None
        # A decoded JSON string can itself be a bare URL (possibly with
        # escaped slashes, which the regex below never matches) — sanitize
        # the decoded value and re-encode it instead of regexing the
        # escaped original.
        if isinstance(decoded, (dict, list, str)):
            return json.dumps(_redact_evidence(decoded))
        return re.sub(r"\b(?:https?|wss?)://[^\s<>\"'\\]+", "[REDACTED]", value, flags=re.IGNORECASE)
    return value


async def require_bearer_token(authorization: str | None = Header(default=None)) -> None:
    """Require a configured API secret for operations that can start work."""
    expected = os.environ.get(API_TOKEN_ENV)
    if not expected:
        raise HTTPException(
            status_code=503,
            detail=f"API mutations are disabled; configure {API_TOKEN_ENV}.",
        )

    scheme, separator, supplied = (authorization or "").partition(" ")
    if not separator or scheme.lower() != "bearer" or not hmac.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=401,
            detail="A valid bearer token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _configured_db_path() -> str:
    return os.environ.get(DB_PATH_ENV, "shadow_strike_knowledge.sqlite3")


def _reject_fork_url(fork_url: str) -> None:
    """API-triggered Foundry jobs cannot access arbitrary RPC endpoints."""
    if fork_url:
        raise HTTPException(
            status_code=400,
            detail="fork_url is disabled for API jobs; submit an empty value.",
        )


def _queue_job(work: Callable[[], dict]) -> dict[str, str]:
    job_id = uuid.uuid4().hex
    with _jobs_lock:
        _cleanup_jobs()
        if len(_jobs) >= MAX_TRACKED_JOBS:
            raise HTTPException(status_code=503, detail="Job capacity reached; retry later.")
        job = _Job(_job_executor.submit(work))
        _jobs[job_id] = job

    def completed(_future):
        with _jobs_lock:
            job.completed_at = monotonic()

    # A completed future invokes callbacks synchronously; register outside the lock.
    job.future.add_done_callback(completed)
    return {"job_id": job_id, "status": "queued"}


def _cleanup_jobs() -> None:
    """Expire terminal jobs; caller holds _jobs_lock. Active work is never evicted."""
    now = monotonic()
    expired = [
        job_id for job_id, job in _jobs.items()
        if job.completed_at is not None and now - job.completed_at >= JOB_RETENTION_SECONDS
    ]
    for job_id in expired:
        del _jobs[job_id]


def _execute_run(req: RunRequest) -> dict:
    if req.engine == "foundry":
        from shadow_strike.execution.foundry_runner import ForgeRunner

        executor = ForgeRunner(foundry_project_root=".")
    elif req.engine == "mock":
        kinds = {next(iter(req.target_contracts)): "VulnerableVault", "attacker": "ReentrantAttacker"}
        executor = MockExecutor(contract_kinds=kinds)
    else:
        raise ValueError("Unsupported execution engine")

    graph = SimpleShadowStrikeGraph(
        executor=executor,
        verifier=Verifier(),
        library=library,
        max_retries=req.max_retries,
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
        with run_store(db_path=_configured_db_path()) as active_store:
            save_run(
                active_store,
                scenario,
                result.get("execution_result"),
                result.get("verifier_verdict"),
                attempt_number=result["attempt_count"],
                failure_reason=result["stopped_reason"],
            )

    return {
        "engine": req.engine,
        "scenario_id": scenario.scenario_id if scenario else None,
        "stopped_reason": result["stopped_reason"],
        "verified": bool(result["final_proof"]),
        "proof": result["final_proof"],
        "history": result["history"],
    }


def _build_mock_executors(executor_config: dict[str, dict]) -> dict[str, MockExecutor]:
    """Build class-specific mocks from caller-provided executor configuration."""
    return {
        vulnerability_class: MockExecutor(
            contract_kinds=config.get("contract_kinds", {}),
            contract_params=config.get("contract_params", {}),
        )
        for vulnerability_class, config in executor_config.items()
    }


class RunRequest(BaseModel):
    source_code: str
    protocol_name: str
    target_contracts: dict[str, str] = Field(min_length=1)
    fork_url: str = ""
    fork_block: int = Field(default=0, ge=0)
    attacker_initial_eth: float = Field(default=1.0, ge=0, allow_inf_nan=False)
    engine: Literal["mock", "foundry"] = "mock"
    max_retries: int = Field(default=3, ge=0)
    # None means heuristics only; the server-side Anthropic key comes from its environment.
    llm: Literal["anthropic", "echo"] | None = None


class BenchmarkRequest(BaseModel):
    source_code: str
    protocol_name: str
    target_contracts: dict[str, str] = Field(min_length=1)
    executor_config: dict[str, dict] = Field(default_factory=dict)
    attacker_initial_eth: float = Field(default=1.0, ge=0, allow_inf_nan=False)
    fork_url: str = ""
    fork_block: int = Field(default=0, ge=0)


class SentinelRequest(BaseModel):
    """HTTP boundary for the Axiom/Sentinel integration."""

    request_id: str
    target_protocol: str
    source_code: str
    target_contracts: dict[str, str] = Field(min_length=1)
    suspected_vulnerability_class: str | None = None
    executor_config: dict[str, dict] = Field(default_factory=dict)
    attacker_initial_eth: float = Field(default=1.0, ge=0, allow_inf_nan=False)
    fork_url: str = ""
    fork_block: int = Field(default=0, ge=0)


@app.get("/attack-library")
async def list_attack_library():
    # ``_dir`` is useful internally for loading metadata but is a server path,
    # so keep it out of the public API representation.
    entries = []
    for vulnerability_class in library.available_classes():
        entry = dict(library.get(vulnerability_class))
        entry.pop("_dir", None)
        entries.append(entry)
    return entries


@app.get("/attack-library/{vulnerability_class}")
async def get_attack_library_entries(vulnerability_class: str):
    with run_store(db_path=_configured_db_path()) as active_store:
        rows = active_store.library_entries(vulnerability_class)
        return _redact_evidence([dict(row) for row in rows])


@app.post("/runs", status_code=202, dependencies=[Depends(require_bearer_token)])
async def create_run(req: RunRequest):
    _reject_fork_url(req.fork_url)
    return _queue_job(lambda: _execute_run(req))


@app.get("/jobs/{job_id}", dependencies=[Depends(require_bearer_token)])
async def get_job(job_id: str):
    with _jobs_lock:
        _cleanup_jobs()
        job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown job id.")

    future = job.future
    if not future.done():
        return {"job_id": job_id, "status": "running" if future.running() else "queued"}
    try:
        return {"job_id": job_id, "status": "complete", "result": _redact_evidence(future.result())}
    except Exception:  # noqa: BLE001 — exception messages may contain credentials
        return {"job_id": job_id, "status": "failed", "error": "Job execution failed."}


@app.get("/runs/{scenario_id}", dependencies=[Depends(require_bearer_token)])
async def get_run(scenario_id: str):
    with run_store(db_path=_configured_db_path()) as active_store:
        rows = active_store.attempts_for_scenario(scenario_id)
        return _redact_evidence([dict(row) for row in rows])


def _execute_benchmark(req: BenchmarkRequest) -> dict:
    report = run_benchmark(
        target_contract_source=req.source_code,
        target_protocol_name=req.protocol_name,
        target_contracts=req.target_contracts,
        executors=_build_mock_executors(req.executor_config),
        fork_url=req.fork_url,
        fork_block=req.fork_block,
        attacker_initial_eth=req.attacker_initial_eth,
        library=library,
        db_path=_configured_db_path(),
    )
    return {
        "target_protocol": report.target_protocol,
        "hypotheses_flagged": report.hypotheses_flagged,
        "results": [
            {
                "vulnerability_class": result.vulnerability_class,
                "status": result.status,
                "scenario_id": result.scenario_id,
                "detail": result.detail,
                "proof_artifact": result.proof_artifact,
            }
            for result in report.results
        ],
        "scorecard_text": report.scorecard(),
    }


@app.post("/benchmark", status_code=202, dependencies=[Depends(require_bearer_token)])
async def create_benchmark(req: BenchmarkRequest):
    """Queue a benchmark; poll its job ID rather than holding the request open."""
    _reject_fork_url(req.fork_url)
    return _queue_job(lambda: _execute_benchmark(req))


def _execute_sentinel(req: SentinelRequest) -> dict:
    sentinel_req = SentinelHypothesisRequest(
        request_id=req.request_id,
        target_protocol=req.target_protocol,
        source_code=req.source_code,
        target_contracts=req.target_contracts,
        suspected_vulnerability_class=req.suspected_vulnerability_class,
        attacker_initial_eth=req.attacker_initial_eth,
        fork_url=req.fork_url,
        fork_block=req.fork_block,
    )
    response = handle_sentinel_request(
        sentinel_req,
        _build_mock_executors(req.executor_config),
        library,
        db_path=_configured_db_path(),
    )
    return {
        "request_id": response.request_id,
        "verified": response.verified,
        "severity": response.severity,
        "scenario_id": response.scenario_id,
        "tested_classes": response.tested_classes,
        "recommendation": response.recommendation,
        "proof_artifact": response.proof_artifact,
    }


@app.post("/sentinel/hypothesis", status_code=202, dependencies=[Depends(require_bearer_token)])
async def sentinel_hypothesis(req: SentinelRequest):
    _reject_fork_url(req.fork_url)
    return _queue_job(lambda: _execute_sentinel(req))
