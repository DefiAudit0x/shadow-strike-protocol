# Changelog

All notable changes to Shadow Strike Protocol, in the order they were
actually built. Kept honest on purpose: entries note what was tested
live versus what was written but needs infrastructure this project
was built without (network, a real LLM key, Postgres, Foundry).

## [0.6.1] — first real Foundry run (on GitHub Actions, not this sandbox)

### Fixed
- **Real bug #4, and the first one caught on an actual EVM rather than
  the Python mock**: `VaultReentrancy.t.sol`'s
  `test_reentrancy_drains_vulnerable_vault` asserted the vault would be
  drained to exactly zero. It isn't — `MaliciousReceiver_demo.sol` caps
  reentry at `MAX_REENTRIES = 3` (a deliberate gas/safety bound on the
  attacker contract itself), so the real exploit drains exactly 4 ETH
  (1 initial `withdraw()` + 3 reentrant ones) out of an 11 ETH pool,
  not all of it. Fixed the assertions to check what the bug actually
  guarantees — the attacker profits well beyond their own deposit, and
  the vault loses funds belonging to OTHER depositors, not just the
  attacker's own stake — rather than an unrealistic "fully drained"
  claim. Confirmed against the actual forge trace output (attacker:
  1→5 ETH, vault: 11→7 ETH) before committing the fix.
- Partial `ruff` lint cleanup (import ordering, `typing.Callable` →
  `collections.abc.Callable` per UP035) in `monitoring/watcher.py`,
  `storage/postgres_store.py`, `verifier/verifier.py`,
  `agent/nodes.py` — 4 of the 37 flagged issues, the ones visible in
  the CI log excerpt. The lint job is `continue-on-error: true` so
  this was never blocking; `ruff check --fix` locally will clean up
  the remaining ~32 auto-fixable ones in one pass.

## [0.6.0] — 11/11 vulnerability classes now have live execution proof

### Added
- `TrustingRouter`/`LegitimateComputer`/`MaliciousComputer` — worked
  `cross_contract` example (trust-boundary hijack via an unguarded
  "which contract do we trust" setter).
- `VulnerableProxy`/`MaliciousImplementation` — worked `upgradeability`
  example (unguarded `upgradeTo()` + a real storage-collision mechanism).
- `SelfLiquidationMarket` — worked `economic` example (profitable
  self-liquidation from generous bonus math, no code bug or price
  manipulation involved).

All three live-tested, each with a "this wouldn't work without the
specific flaw" control case. This closes out every one of the 11
Attack Library classes with verified live execution — 7 via automated
`SCENARIO_BUILDERS`, 4 via the hand-authoring path (exactly as the
architecture intended for classes too protocol-specific to genericize).

### Fixed
- **Real economic-modeling bug, caught live, #3**: the first
  `SelfLiquidationMarket.selfLiquidate()` capped payout at
  `min(debt * (1 + bonus), collateral_amt)` — a cap that makes
  genuine profit structurally impossible no matter how generous the
  bonus is, since payout can never exceed what the attacker put in.
  Removed the artificial collateral cap (a real protocol pays the
  bonus from pooled liquidity, not the liquidator's own stake); the
  only real limit is the market's actual on-hand funds, already
  enforced by `Ledger.transfer`'s insufficient-balance check. Verified
  both directions afterward: a generous bonus profits, a conservative
  one doesn't.

## [0.5.0] — flash_loan composition, accounting worked example

### Added
- `MockFlashLender` + `FlashLoanReentrantAttacker` — live demonstration
  of `flash_loan`'s documented composition design (it was never meant
  to be a standalone builder; see `composes_with` in its `meta.yaml`).
  Attacker starts with **zero capital**, borrows atomically, drains via
  reentrancy, repays principal + fee, keeps the remainder. Live-tested
  including a fee-sensitivity check (higher fee → lower attacker
  profit, verified numerically). This brings every templated class
  (7/7) to live-tested status.
- `UncheckedBalanceToken` + `examples/scenarios/accounting_underflow_demo.yaml`
  — a concrete, hand-authored `accounting` scenario (classic uint256
  underflow from unchecked arithmetic). `accounting` still has no
  automated builder by design; this demonstrates the hand-authoring
  path against a real, specific bug rather than leaving the class
  purely theoretical. Live-tested: unchecked version wraps to exactly
  `2**256`; checked version reverts instead.

## [0.4.0] — API surface completion, duplicate cleanup, docs

### Added
- `signature_replay` and `price_manipulation` mock executors
  (`SignedActionTarget`/`SignatureReplayer`, `ERC4626LikeVault`/
  `ShareInflationAttacker`) + scenario builders — live-tested, both
  exploitable and fixed/resistant cases. Brings live-mock-tested
  coverage to 6 of 7 templated classes.
- `POST /benchmark` and `POST /sentinel/hypothesis` endpoints on the
  FastAPI layer, wiring the benchmark runner and the Axiom adapter
  into the same API surface as `/runs`.
- `CONTRIBUTING.md` — the add-a-vulnerability-class playbook.
- `CHANGELOG.md` (this file).

### Fixed
- **Real bug, caught live**: the first `price_manipulation` scenario
  design checked `total_shares` right after the attacker's own
  donation, which doesn't actually distinguish a vulnerable vault from
  a donation-resistant one (both start near-zero after one tiny
  deposit). Fixed by adding a victim deposit step post-manipulation
  and checking *their* resulting shares instead — the actual
  real-world exploit signature.
- **Duplicate code removed**: `mock_executor.py` ended up with two
  parallel, differently-named implementations of signature-replay and
  share-inflation mocks (`SignatureReplayTarget`/`ShareVault` vs.
  `SignedActionTarget`/`ERC4626LikeVault`) after concurrent edits in
  the same session. Consolidated to one (the live-verified one,
  including the victim-deposit fix above); removed the orphaned test
  file that exercised the deleted classes.

## [0.3.0] — the five roadmap ideas

- `benchmark/runner.py` — scores every Attack-Library-flagged class on
  one contract independently; live-tested on a dual-vulnerability
  synthetic contract.
- `integrations/axiom_adapter.py` — `handle_sentinel_request()`, two
  call paths (targeted class / full benchmark); live-tested with
  synthetic requests (not against the real Axiom codebase, which
  isn't available in this environment).
- `monitoring/watcher.py` — `ContinuousMonitor` (dispatch/alert/
  regression-detection), live-tested with synthetic deployment events
  including a resisted→exploitable regression across two events.
  `EVMChainWatcher.poll()` is a documented interface, not a working
  poller — needs a real RPC connection this environment doesn't have.
- `examples/historical_incidents/` — The DAO (2016), Parity Multisig
  freeze (2017), Mango Markets (2022) reconstructed as YAML scenarios
  and verified live. Explicit honesty notes: simplified reconstructions
  from general knowledge of public post-mortems, not byte-for-byte
  replays; Mango specifically flagged as real-Solana vs.
  modeled-as-EVM-generic.
- `BLOG_POST.md` — technical write-up, written in English per the
  project's international (LinkedIn/Kaggle) audience.

## [0.2.0] — packaging, CI, hand-authoring workflow

- `pyproject.toml` — real installable package; live-tested
  (`pip install -e .`, `shadow-strike` console command run from
  outside the project directory).
- `.github/workflows/ci.yml`, `Makefile`.
- `core/scenario_loader.py` + `cli.py run-scenario` / `save-scenario` —
  the hand-authoring path for vulnerability classes with no automatic
  builder. Live-tested end to end including YAML round-trip.
- `dashboard/index.html` — static page consuming the FastAPI layer.
  Not live-tested (needs `uvicorn` running).

## [0.1.0] — hardening pass

- `oracle_manipulation` (AMM pool + lending market mocks) and
  `access_control` live mock support — both exploitable and
  resisted/guarded cases tested.
- **Real bug caught live**: initial oracle_manipulation economics had
  `spot_price()` direction inverted and collateral disconnected from
  actual swap output, making the "attack" unprofitable even against a
  thin pool. Fixed and re-verified.
- All 11 Attack Library vulnerability classes registered (7 with
  executable Solidity templates; 4 documented as roadmap with explicit
  architectural justification for why they resist genericization).
- `execution/sandbox.py` — OS-level resource limits via
  `resource.setrlimit`; live-tested by actually killing a runaway
  process.
- `docker/sandbox.Dockerfile` — container-isolation layer, written,
  not built here (no Docker in this environment).
- Real `state_diff` capture via Foundry's actual `vm.record()`/
  `vm.accesses()` cheatcodes (previously a TODO stub).
- `agent/llm_providers.py` (`AnthropicLLM`, stdlib-only) — written,
  not live-tested (no network/API key here); `EchoLLM` test double
  live-tested through the full graph.
- `reporting/report_generator.py` — DeFiAudit-style Markdown findings;
  live-tested against a real verified proof.
- `storage/postgres_store.py` — SQLAlchemy/Postgres, same interface as
  the SQLite `KnowledgeStore`; written, not live-tested (no
  sqlalchemy/Postgres here).

## [0.0.1] — initial build

- Core engine: `AttackScenario` schema (dataclasses, zero deps),
  `safe_eval` (AST-allowlist expression evaluator — self-tested
  against a code-injection attempt), `ScenarioCompiler` (scenario ->
  real Foundry `.t.sol`), `MockExecutor` (offline EVM-like simulator),
  `Verifier`, SQLite `KnowledgeStore`.
- `reentrancy` end-to-end: real vulnerable `Vault.sol` + `SafeVault.sol`,
  live-verified exploit, re-run against the patched contract to confirm
  the fix holds.
- `SimpleShadowStrikeGraph` (zero-dep orchestrator) +
  `graph_langgraph.py` (production LangGraph version, written not
  live-tested here).
- 19 tests passing at this stage.
