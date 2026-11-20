# Contributing to Shadow Strike Protocol

## Adding a new vulnerability class (or a mock executor for an existing roadmap class)

This is the most common contribution shape. Follow this order — each
step is independently testable, so you can verify as you go instead of
debugging a big-bang addition.

### 1. Attack Library metadata (`attack_library/<class_name>/`)
Add `meta.yaml` with `vulnerability_class`, `display_name`, `description`,
`default_invariants`, `default_success_conditions`, and
`heuristic_source_patterns` (recon hints — weak signals, never a verdict
on their own). Metadata alone does not add automated scenario support;
that requires the registered builder in step 3.

Attacker contract templates are not supported. For Foundry scenarios
that need an attacker contract, write a concrete Solidity contract and
supply its name and import path via `ScenarioCompiler`'s
`attacker_contract_name` and `attacker_import_path` arguments. The
compiler imports that existing contract; it does not generate it from
library metadata. See `contracts/src/attackers/MaliciousReceiver_demo.sol`
and `examples/run_demo.py` for this explicit contract path. Check generated
Solidity with `forge build` before any separately authorized execution.

### 2. Mock executor support (`execution/mock_executor.py`)
Add the Python classes that model the vulnerable (and, ideally, fixed)
version of whatever this class targets, mirroring the real Solidity
semantics closely enough that the exploit mechanics are genuine, not
asserted. Register them in `CONTRACT_REGISTRY`. If a class needs
cross-contract references (a pool referencing a market, say), wire
construction through the `pending_refs` two-pass pattern already used
for `OracleFedLendingMarket` / `OracleManipulationAttacker`.

**Before you commit, prove the exploit is real**: write a throwaway
script that runs your mock through `Verifier`, against both the
vulnerable and (if applicable) fixed contract variant, and confirm the
verdict flips correctly. Finding the "the fix doesn't actually resist
the attack in my model" bug *before* it's a test case has happened
more than once in this codebase's history — see `price_manipulation`'s
victim-deposit fix in the commit history for a concrete example.

### 3. Scenario builder (`agent/nodes.py`)
Add a `_build_<class>_scenario(...)` function and register it in
`SCENARIO_BUILDERS`. This is what lets the automated pipeline (not just
hand-authored YAML) propose scenarios for your new class.

### 4. Tests (`tests/`)
At minimum: one test proving the vulnerable case verifies, one proving
the fixed/resistant case does NOT verify. Both executions, not
assertions about what "should" happen — the whole point of this project
is that claims are backed by execution.

### 5. Run the full suite
    make test
All existing tests must still pass. `make demo` should also still
complete cleanly.

## Adding a class with NO automated builder (accounting, upgradeability, cross_contract, economic, or your own bespoke one-off)

Skip steps 1–3 above (or add only step 1's `meta.yaml` and document
that automated scenario building is unsupported). Write the scenario
directly as YAML via `core/scenario_loader.py` — see
`examples/historical_incidents/` for worked examples of this path, and
`examples/scenarios/reentrancy_demo.yaml` for the minimal shape.

## Code style

- No new required dependencies in the core engine (`core/`,
  `execution/mock_executor.py`, `execution/compiler.py`,
  `verifier/`, `storage/db.py`, `agent/graph_simple.py`,
  `agent/nodes.py`, `attack_library/`) — it must keep running with
  only `jinja2` + `pyyaml`. Anything needing more (real LLM calls,
  Postgres, FastAPI) goes in a module that fails with a clear
  `ImportError` message, not a silent one, if the optional dependency
  is missing (see `agent/llm_providers.py` or `storage/postgres_store.py`
  for the pattern).
- Every mock contract class that exposes state beyond ETH balances
  should implement `state_vars() -> dict` — this is what lets
  `success_conditions` reference it via `safe_eval` without special-
  casing in the executor (see `AccessControlTarget.state_vars()`).
- Don't use Python's `eval()` anywhere near scenario-derived strings.
  Extend `core/safe_eval.py`'s allowlisted AST walker instead if you
  need a new expression capability.

## Reporting a bug in Shadow Strike itself (not a scenario finding)

Open an issue with: the scenario YAML (or the Python that constructed
it), the executor config used, and the actual vs. expected
`VerificationResult`. If it's a mock-executor economics bug (a
contract that "should" resist an attack but doesn't, or vice versa),
that's exactly the kind of bug this project's own test suite exists to
catch — a fix without a regression test won't be considered complete.
