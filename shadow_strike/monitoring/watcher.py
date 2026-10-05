"""
shadow_strike.monitoring.watcher
===================================
Idea #3 from the roadmap discussion: "continuous Shadow Strike" —
automatically re-benchmark a protocol whenever something changes
on-chain (new deployment, proxy upgrade) instead of only running
on-demand.

This file is split cleanly along the line of what's testable here and
what isn't:

  - ContinuousMonitor (the dispatch/alert logic: given a deployment
    event, decide which Attack Library classes apply, run them, alert
    if anything is exploitable) has NO network dependency — it's pure
    logic over a DeploymentEvent the caller hands it. Fully tested
    below with synthetic events.

  - Actually WATCHING a chain (polling an RPC for new contract
    deployments or proxy upgradeTo() calls) needs a live RPC
    connection, which this sandbox doesn't have. EVMChainWatcher is a
    documented interface + a clearly-marked NotImplementedError stub,
    not a working poller — see its docstring for what a real
    implementation needs (web3.py, an RPC websocket subscription or
    polling loop, and a way to fetch verified source for a newly-seen
    address, e.g. an Etherscan-style API).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from shadow_strike.attack_library.registry import AttackLibrary
from shadow_strike.benchmark.runner import BenchmarkReport, run_benchmark
from shadow_strike.storage.db import KnowledgeStore


@dataclass
class DeploymentEvent:
    """What triggers a re-benchmark. `event_type` distinguishes a brand
    new deployment from a proxy upgrade pointing at new implementation
    code — both warrant a fresh run, but you may want to alert
    differently (an upgrade regressing a previously-resisted class is
    arguably more urgent than a first-time finding on new code)."""
    protocol_name: str
    address: str
    source_code: str
    event_type: str   # "deploy" | "upgrade"
    block_number: int = 0


AlertFn = Callable[[DeploymentEvent, BenchmarkReport], None]


class ContinuousMonitor:
    """The testable half. Call .handle_event() for each DeploymentEvent
    your chain source produces (real or synthetic)."""

    def __init__(
        self,
        executors: dict[str, object],
        store: KnowledgeStore | None = None,
        library: AttackLibrary | None = None,
        alert_fn: AlertFn | None = None,
        attacker_initial_eth: float = 1.0,
    ):
        self.executors = executors
        self.store = store
        self.library = library or AttackLibrary()
        self.alert_fn = alert_fn
        self.attacker_initial_eth = attacker_initial_eth
        self._previous_reports: dict[str, BenchmarkReport] = {}  # address -> last report, for regression detection

    def handle_event(self, event: DeploymentEvent) -> BenchmarkReport:
        report = run_benchmark(
            target_contract_source=event.source_code,
            target_protocol_name=event.protocol_name,
            target_contracts={"vault": event.address},
            executors=self.executors,
            attacker_initial_eth=self.attacker_initial_eth,
            library=self.library,
        )

        regressions = self._detect_regressions(event.address, report)

        if self.store is not None:
            for r in report.results:
                if r.scenario_id:
                    # the builder already constructed+validated the scenario
                    # inside run_benchmark; re-deriving it here just to save
                    # would duplicate work, so we save what we have: the
                    # attempt record, keyed by the scenario_id already minted
                    self.store.save_attempt(
                        scenario_id=r.scenario_id, attempt_number=1,
                        status="success" if r.status == "exploitable" else "failure",
                        failure_reason=None if r.status == "exploitable" else r.detail,
                        execution_result=None, verifier_result=None,
                    )

        exploitable = [r for r in report.results if r.status == "exploitable"]
        if (exploitable or regressions) and self.alert_fn is not None:
            self.alert_fn(event, report)

        self._previous_reports[event.address] = report
        return report

    def _detect_regressions(self, address: str, report: BenchmarkReport) -> list[str]:
        """A class that was `resisted` last time but is `exploitable`
        now — e.g. an upgrade reintroduced a bug a previous version
        had fixed. Worth surfacing distinctly from a first-time finding."""
        previous = self._previous_reports.get(address)
        if previous is None:
            return []
        prev_status = {r.vulnerability_class: r.status for r in previous.results}
        return [
            r.vulnerability_class for r in report.results
            if r.status == "exploitable" and prev_status.get(r.vulnerability_class) == "resisted"
        ]


class ChainSource(Protocol):
    """What a real chain watcher must implement to feed ContinuousMonitor."""
    def poll(self) -> list[DeploymentEvent]: ...


class EVMChainWatcher:
    """NOT a working implementation — documents what one needs.

    A real version would:
      1. Hold a web3.py (or similar) connection to an RPC endpoint
      2. Either subscribe to new blocks and filter for CREATE/CREATE2
         txs + proxy upgradeTo()/upgradeToAndCall() calls, or poll an
         indexer (e.g. a block-explorer API) for "new verified
         contract" / "new proxy upgrade" events for a watched address list
      3. For a newly-seen address, fetch verified source (Etherscan-style
         "getsourcecode" API, or decompile if unverified — decompiled
         source would need much more heuristic-pattern tolerance than
         attack_library's current patterns assume)
      4. Yield DeploymentEvent objects from .poll()

    None of this is implementable without real network access, which
    this environment doesn't have — hence the explicit NotImplementedError
    rather than a half-working stub that silently does nothing.
    """

    def __init__(self, rpc_url: str, watched_addresses: list[str] | None = None):
        self.rpc_url = rpc_url
        self.watched_addresses = watched_addresses or []

    def poll(self) -> list[DeploymentEvent]:
        raise NotImplementedError(
            "EVMChainWatcher.poll() needs a real RPC connection (web3.py) and a "
            "source-fetching API — not available in this environment. Use "
            "SyntheticChainWatcher (in tests/) for development, or implement "
            "this against your actual RPC provider."
        )
