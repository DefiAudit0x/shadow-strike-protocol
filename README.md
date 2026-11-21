# Shadow Strike Protocol

> An interactive attack-simulation lab for smart contracts — it turns a
> security hypothesis into an attack that is actually executed, proven
> through real state transitions, not guessed by a language model.

This is a real, working implementation of the architecture described in
`ARCHITECTURE.md`. It was built on one strict principle: **reasoning (the
LLM) never decides whether an attack succeeded — deterministic execution +
verification decide.**

## Instant run (no installation)

The core engine runs with no external dependency except `jinja2` and
`pyyaml` (both common and usually already installed). No Foundry, RPC, or
API key is needed to try the full pipeline:

```bash
pip install -r requirements.txt   # jinja2 + pyyaml only
PYTHONPATH=. python3 examples/run_demo.py
```

This actually executes — in practice, not in theory:

1. **Recon** that is real, on `contracts/src/Vault.sol` (a contract with a real reentrancy vulnerability)
2. **Hypothesis generation** based on attack-library patterns (`attack_library/`)
3. A fully validated **AttackScenario** build (dataclass validation)
4. **Real execution** of the attack through a miniature EVM simulator (`MockExecutor`) — not a claim,
   but a real ETH ledger with correct reentrancy semantics
5. Generation of a real Foundry test (`.t.sol`) from that exact same scenario —
   ready to run with `forge test` once Foundry + RPC are available
6. Deterministic **Verification** via `safe_eval` (not the dangerous `eval()`)
7. **Proof storage** in the Knowledge Store (SQLite)
8. **Replaying the exact same scenario** against `SafeVault` (the fixed version) to prove
   the fix holds — `ATTACK FAILED` here is the desired result

```bash
PYTHONPATH=. python3 -m unittest discover -s tests -v
PYTHONPATH=. python3 -m shadow_strike.cli library        # show the attack library
```

## Layout

```
shadow_strike/
├── core/            # AttackScenario schema + safe_eval (zero deps)
├── attack_library/  # plugins: reentrancy (complete), access_control (complete),
│                     #          oracle_manipulation / flash_loan (roadmap)
├── execution/
│   ├── compiler.py          # Scenario -> real Foundry .t.sol
│   ├── foundry_runner.py    # real production execution (requires forge + RPC)
│   └── mock_executor.py     # instant execution without a network (for dev/demo/CI)
├── verifier/        # the deterministic judge — no LLM here at all
├── storage/         # Knowledge Store (SQLite here, Postgres in production)
├── agent/
│   ├── nodes.py             # the six nodes: recon/hypothesis/planner/
│   │                         # executor/verifier/critic
│   ├── graph_simple.py      # dependency-free coordinator — works now
│   └── graph_langgraph.py   # production LangGraph version (pip install langgraph)
├── api/main.py      # FastAPI (pip install fastapi uvicorn)
└── cli.py

contracts/
├── src/Vault.sol              # the vulnerable target (real reentrancy)
├── src/SafeVault.sol          # same interface, fixed
├── src/attackers/             # hand-written attacker contracts
└── test/                       # Foundry tests (hand-written + auto-generated)
```

## API security and jobs

The optional FastAPI service is intended to be bound to a trusted local or
private network. Configure a secret before starting it; all `POST` routes
(`/runs`, `/benchmark`, and `/sentinel/hypothesis`) require the header
`Authorization: Bearer <token>` and return `202 Accepted` with a `job_id`.
Poll `GET /jobs/{job_id}` with the same bearer token to read `queued`,
`running`, `complete`, or `failed` status. Jobs run in a bounded in-process
worker pool, so their status is available only to the current API process.

```bash
export SHADOW_STRIKE_API_TOKEN="replace-with-a-long-random-secret"
# Optional; defaults to ./shadow_strike_knowledge.sqlite3 and is opened lazily.
export SHADOW_STRIKE_DB_PATH="$PWD/shadow_strike_knowledge.sqlite3"
uvicorn shadow_strike.api.main:app --host 127.0.0.1
```

The dashboard prompts for the bearer token and sends it with run and job-poll
requests. Use HTTPS if the dashboard or API is accessed beyond localhost, and
do not embed the server token in a publicly served dashboard. The API rejects
every non-empty `fork_url`; API-triggered Foundry runs therefore cannot select
an RPC endpoint, while local CLI runs remain available for forked scenarios.
The placeholder streaming WebSocket was removed; job polling is the supported
progress interface. Importing `shadow_strike.api.main` does not create the
SQLite database; the configured store is opened only when persistence is used.

## What has been completed since the first version

| Item | Status |
|---|---|
| 11/11 vulnerability classes in the attack library | Registered as metadata in `meta.yaml`; automated scenarios need a registered builder and executor support. Attacker contracts are not generated from the library; a hand-written Solidity contract is passed to the compiler when needed |
| `oracle_manipulation` live | `SimplePool` + `OracleFedLendingMarket` + `OracleManipulationAttacker` in `mock_executor.py` — a real, tested price-manipulation attack (a thin pool is exploited, a deep pool holds) |
| `access_control` live | `AccessControlTarget` — a broken guard is exploited, an enabled guard blocks the attack |
| Forge resource limits | `execution/sandbox.py` enforces host CPU and memory limits via `resource.setrlimit`; the Docker container is manual-only |
| Real `state_diff` | `compiler.py` generates `vm.record()`/`vm.accesses()` (real forge-std cheatcodes), `foundry_runner.py` parses the output |
| Real LLM wiring | `agent/llm_providers.py` — `AnthropicLLM` (stdlib only, no SDK) ready for a real API key; `EchoLLM` for offline testing (verified live) |
| DeFiAudit integration | `reporting/report_generator.py` — turns any proof into a professional audit-format Markdown finding (verified live, see the example in `examples/run_demo.py` step 10) |
| Postgres for production | `storage/postgres_store.py` — exactly the same `KnowledgeStore` interface (drop-in) + `migrate_from_sqlite()` |

**Important honesty note**: the following items are written and structurally checked (`py_compile`) but **not verified live** in this environment because they need a network / dependencies not available here: `AnthropicLLM` (needs a real API key), `postgres_store.py` (needs `sqlalchemy` + Postgres), `api/main.py` (needs `fastapi`), the fine details of `foundry_runner.py`'s `--json` format (needs a real Foundry — the general shape is documented, but different forge versions may change the JSON shape slightly, so test it on first use).

## What was completed in this round (packaging + CI + hand-authored scenarios)

| Item | Status |
|---|---|
| `pyproject.toml` | A real Python package, **verified live**: `pip install -e .` succeeded, and the `shadow-strike library` command ran from `/tmp` (entirely outside the project folder) — proof the packaging is genuinely sound |
| `.github/workflows/ci.yml` | 4 jobs: tests on 3.10/3.11/3.12, lint, local Foundry tests (no fork — they work even from forks), production-module import check |
| `Makefile` | `make test` / `make demo` / `make sandbox-selftest` — **verified live** |
| **Hand-authored scenarios (`core/scenario_loader.py`)** | This is the real path for the `accounting` / `upgradeability` / `cross_contract` / `economic` classes, which have no automatic builder: you write the scenario in YAML, it goes through the exact same `AttackScenario` validation, then runs through the same pipeline. **Fully verified live**: `shadow-strike run-scenario --file examples/scenarios/reentrancy_demo.yaml` executed and verified the attack via the actually installed command; `shadow-strike save-scenario` exported the result back as editable YAML |
| `dashboard/index.html` | A simple monitoring/run dashboard consuming `api/main.py` — no build step, no external CDN. **Not verified live** (needs a `uvicorn` actually running) |

```bash
# Any researcher adding a hand-written scenario for a vulnerability class with no automatic builder:
shadow-strike run-scenario --file my_scenario.yaml --engine mock \
    --mock-kinds vault=VulnerableVault --mock-kinds attacker=ReentrantAttacker
```

## 11/11 — every vulnerability class now has a live execution proof

I added 3 hand-written examples covering the last 3 classes that were entirely roadmap:

- **`cross_contract`**: `TrustingRouter` lets anyone change the "trusted contract" it consults for authorization — the attacker points trust at a contract they control and authorizes themselves for any amount. Verified live, including the case where, with no hijack, the legitimate contract rejects the same request.
- **`upgradeability`**: `VulnerableProxy` with no access control on `upgradeTo()` + a real storage collision — a malicious implementation writes directly over the owner slot. Verified live.
- **`economic`**: `SelfLiquidationMarket` — an overly generous liquidation bonus lets the attacker liquidate their own position at a profit, with no price manipulation or code bug, just incentive math. **Found and fixed a third economic bug here by actually running it**: the first version capped the payout at the attacker's own collateral, which makes a real profit mathematically impossible no matter how large the bonus — fixed it (the real cap must be the protocol's liquidity, not the attacker's own capital), and proved both versions: a generous bonus (20%) = real profit, a conservative bonus (5%) = real loss.

The result: **all 11 classes (not just the 7 with automatic builders) now have a live, verified execution proof** — the only difference is that these 4 classes go through the hand-authored (YAML) path instead of automatic building, which matches the original architecture design exactly.

## flash_loan and accounting — the last two gaps

- **`flash_loan` is now fully live** — not a standalone builder (deliberately designed to compose with another class, see `composes_with` in meta.yaml), but I now have a real `MockFlashLender` + `FlashLoanReentrantAttacker`: a **zero-capital** attacker borrows via flash loan, enters with the same reentrancy pattern, repays the loan + fee, and walks away with a net profit. Verified live, including fee sensitivity (a higher fee = less profit, checked numerically). All 7 classes that have a template now have live execution (7/7).
- **A practical `accounting` example** — this class deliberately has no automatic builder (the architecture states explicitly that accounting bugs are protocol-specific). Instead of leaving it entirely theoretical, I built a hand-written example: `UncheckedBalanceToken` — a real bug (uint256 underflow from an `unchecked` operation); an attacker with zero tokens transfers more than their balance, overflowing the balance to exactly 2^256. Verified live, including the fixed version (checked=True) that rejects the operation instead of overflowing.

## Cleanup after the five ideas

- **`signature_replay` and `price_manipulation` are now live** (they had a template but no mock) — now 6 of the 7 coded classes have live, verified execution (the only one missing: `flash_loan`, because it is composable with others by its original design).
- **A second real bug exposed by actually running it**: the first version of the `price_manipulation` scenario checked `total_shares` right after the attacker's own attack — which does not actually distinguish a vulnerable vault from a hardened one (both start near zero after a single small deposit). The fix: add a "victim" deposit step after the manipulation and check her share — that is the real signature of the exploit.
- **Real code duplication found and cleaned**: I found two parallel copies of the same logic (`SignatureReplayTarget`/`ShareVault` vs `SignedActionTarget`/`ERC4626LikeVault`) under different names in the same file — merged them into one verified copy and deleted the orphan test file tied to the deleted copy.
- **`/benchmark` and `/sentinel/hypothesis`** were added to `api/main.py` — the API now covers all five ideas, not just plain runs.
- **`CONTRIBUTING.md`** — a complete step-by-step guide to adding a new vulnerability class.
- **`CHANGELOG.md`** — a full log of the build journey, honestly distinguishing "verified live" from "written but needs infrastructure".

## The five ideas (from a later roadmap discussion) — all built and verified live now

| Idea | Where | Status |
|---|---|---|
| **1. Real historical incidents** | `examples/historical_incidents/` | 3 incidents (The DAO, Parity Multisig freeze, Mango Markets) rebuilt as YAML scenarios and **verified live**. An honest warning is written clearly: simplified rebuilds from public post-mortems, not a literal replay of the same bytecode. Mango is specifically marked as having been on Solana, not EVM |
| **2. Axiom/Sentinel integration** | `shadow_strike/integrations/axiom_adapter.py` | A clean Python interface (`handle_sentinel_request`) — with two paths: a specific hypothesis from Sentinel, or a full benchmark if it has none. **Verified live** on both paths. Not wired to the real Axiom code (not available here) but the contract is ready |
| **3. Continuous monitoring** | `shadow_strike/monitoring/watcher.py` | The dispatch/alert/regression-detection logic is **fully verified live** (synthetic events) — including detecting that an upgrade reintroduced a previously fixed vulnerability. Actual on-chain polling (`EVMChainWatcher.poll`) is only a documented interface, raising `NotImplementedError` with an explicit explanation of why (it needs a real RPC + web3.py) |
| **4. Benchmark/scorecard** | `shadow_strike/benchmark/runner.py` | Tries every vulnerability class its heuristics match independently and produces a scorecard. **Verified live** against a contract with two vulnerability classes at once |
| **5. Technical article** | `BLOG_POST.md` | A complete article ready to publish (in English — an assumption based on your international audience on LinkedIn/Kaggle; tell me if you want it in Arabic) |

## Upgrading to full production

Every "light" component here has a documented production alternative inside the code itself (a docstring at the top of each file explains the difference exactly):

| Here now (zero-dep) | Production |
|---|---|
| `dataclasses` in `core/models.py` | Pydantic v2 (JSON schema export) |
| `MockExecutor` | `ForgeRunner` (requires Foundry and RPC when using a fork) |
| `SimpleShadowStrikeGraph` | `graph_langgraph.py` (checkpointing, streaming) |
| SQLite | Postgres (exactly the same schema) |
| Heuristic-based hypothesis/critic | Wiring `llm_fn` to any real LLM client |

The host subprocess is the only supported `ForgeRunner` execution path.
Resource limits do not isolate filesystem or network access. The Docker
container is manual-only, and its [RPC egress allowlist](docker/egress-allowlist-README.md)
is aspirational and unenforced.

```bash
# To run against a real Foundry once available:
forge install foundry-rs/forge-std
export MAINNET_RPC_URL=https://...
python3 -m shadow_strike.cli run \
    --source contracts/src/Vault.sol --protocol MyVault \
    --target vault=0xRealAddress --fork-url $MAINNET_RPC_URL \
    --fork-block 19000000 --engine foundry
```

## Ethical and legal warning

Every generated contract carries an explicit comment: **do not run any
scenario here against a real protocol you do not own or do not have written
authorization to test.** This is a security-research lab; using it outside a
local fork / testnet / explicit authorization from the target protocol is
entirely outside the purpose it was built for.

## Full architectural details

See `ARCHITECTURE.md` for the full architecture (17 sections), including the
roadmap for upcoming phases (additional plugins for oracle manipulation and
flash loan, full sandboxing via Docker, direct integration with DeFiAudit).
