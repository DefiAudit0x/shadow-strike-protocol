#!/usr/bin/env python3
"""
End-to-end live demo — runs entirely offline, zero external deps.

What this proves, in order:
  1. recon_node reads real Solidity source and flags the dangerous line
  2. hypothesis_node matches it against the Attack Library's heuristic
     patterns and proposes a reentrancy hypothesis
  3. scenario_planner_node builds a fully-typed, VALIDATED AttackScenario
     (try mutating it into something invalid — it'll reject before step 4)
  4. ScenarioCompiler renders that exact scenario into real Foundry
     Solidity (written to contracts/test/generated/ for a compile-only
     `forge build` check; no EVM execution is performed)
  5. MockExecutor independently *runs* the same scenario against a
     pure-Python twin of contracts/src/Vault.sol and produces real
     state transitions (no assertion, no guess — an actual balance ledger)
  6. Verifier evaluates success_conditions against those state
     transitions using safe_eval (not eval()) and renders a verdict
  7. The proof is written to the Knowledge Store (SQLite)
  8. The SAME scenario is re-run against SafeVault's mock twin to show
     the attack correctly FAILS once the ordering bug is fixed

Run: PYTHONPATH=. python3 examples/run_demo.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from shadow_strike.agent.graph_simple import SimpleShadowStrikeGraph
from shadow_strike.execution.mock_executor import MockExecutor
from shadow_strike.execution.compiler import ScenarioCompiler
from shadow_strike.verifier.verifier import Verifier
from shadow_strike.storage.db import KnowledgeStore
from shadow_strike.attack_library.registry import AttackLibrary

ROOT = Path(__file__).parent.parent


def validate_demo_outcomes(result, safe_result, safe_verdict):
    if not result.get("final_proof") or not result.get("verifier_verdict"):
        raise RuntimeError("positive control did not produce verified evidence")
    if not result["verifier_verdict"].verified:
        raise RuntimeError("positive control verdict was not verified")
    if safe_result.reverted and safe_result.revert_reason:
        raise RuntimeError(f"negative control execution errored: {safe_result.revert_reason}")
    if safe_verdict.verified:
        raise RuntimeError("negative control unexpectedly verified")


def validate_rendered_contract(path: Path) -> None:
    # The demo gates on a REAL compiler check: the emitted file must build.
    # The toolchain comes from the caller's environment (FOUNDRY_SOLC /
    # FOUNDRY_REMAPPINGS set by the local harness, or the repo's own
    # foundry.toml + lib/forge-std in a normal checkout / CI) — never from
    # hardcoded paths, so this works in any checkout.
    if shutil.which("forge") is None:
        raise RuntimeError("forge is not on PATH; cannot validate the rendered contract")
    relative = path.relative_to(ROOT)
    completed = subprocess.run(
        ["forge", "build", str(relative)], cwd=ROOT, env=os.environ.copy(),
        capture_output=True, text=True,
    )
    if completed.returncode:
        raise RuntimeError(f"forge build failed for {relative}:\n{completed.stdout}{completed.stderr}")


def section(title: str):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def main():
    vault_source = (ROOT / "contracts/src/Vault.sol").read_text()

    section("STEP 0 — target source (contracts/src/Vault.sol)")
    print(vault_source)

    # ---- run the full reasoning + proof-cycle loop against the VULNERABLE vault
    section("STEP 1-7 — running SimpleShadowStrikeGraph against Vault (vulnerable)")

    store = KnowledgeStore(db_path=str(ROOT / "shadow_strike_knowledge.sqlite3"))
    library = AttackLibrary()
    executor = MockExecutor(contract_kinds={"vault": "VulnerableVault", "attacker": "ReentrantAttacker"})
    verifier = Verifier()

    def on_step(label, state):
        print(f"  [{label}] ...", end=" ")
        if label == "recon":
            print(state["recon_notes"])
        elif label == "hypothesis":
            print(f"{len(state['hypotheses'])} hypothesis(es) generated")
        elif label == "scenario_planner":
            s = state.get("current_scenario")
            print(f"scenario {s.scenario_id if s else None} built" if s else "no scenario (see planner_error)")
        elif label == "executor":
            r = state["execution_result"]
            print(f"engine={r.engine} reverted={r.reverted}" if r else "skipped")
        elif label == "verifier":
            v = state["verifier_verdict"]
            print(f"verified={v.verified}" if v else "skipped")
        elif label == "critic":
            print(f"adjustment={state.get('_critic_adjustment')}")

    graph = SimpleShadowStrikeGraph(executor=executor, verifier=verifier, library=library, max_retries=3)
    result = graph.run(
        target_contract_source=vault_source,
        target_protocol_name="DemoVault",
        fork_url="",  # offline, compile-only Foundry output; no RPC needed
        fork_block=0,
        target_contracts={"vault": "0x1111111111111111111111111111111111111111"},
        attacker_initial_eth=1.0,
        on_step=on_step,
    )

    section(f"RESULT: {result['stopped_reason'].upper()}")
    scenario = result["current_scenario"]
    store.save_scenario(scenario)
    status = "success" if result["final_proof"] else "failure"
    attempt_id = store.save_attempt(
        scenario_id=scenario.scenario_id,
        attempt_number=result["attempt_count"],
        status=status,
        failure_reason=None if status == "success" else result["stopped_reason"],
        execution_result=result["execution_result"].to_dict() if result.get("execution_result") else None,
        verifier_result=result["verifier_verdict"].to_dict() if result.get("verifier_verdict") else None,
    )

    if result["final_proof"]:
        print("ATTACK VERIFIED ✔")
        proof = result["final_proof"]
        print(json.dumps({
            "scenario_id": scenario.scenario_id,
            "attacker_eth_before": proof["state_vars"]["attacker"]["eth_balance_before"],
            "attacker_eth_after": proof["state_vars"]["attacker"]["eth_balance_after"],
            "vault_eth_before": proof["state_vars"]["vault"]["eth_balance_before"],
            "vault_eth_after": proof["state_vars"]["vault"]["eth_balance_after"],
            "condition_results": proof["condition_results"],
            "invariant_violations": proof["invariant_violations"],
        }, indent=2))
        proof_id = store.save_proof(
            attempt_id=attempt_id,
            proof_artifact=proof,
            critical_transition="deposit -> attack -> withdraw -> receive() -> withdraw (reentrant)",
        )
        lib_entry_id = store.add_library_entry(
            vulnerability_class="reentrancy",
            scenario_template=scenario.to_dict(),
            tags=["demo", "checks-effects-interactions"],
        )
        print(f"\nstored: proof={proof_id}  attack_library_entry={lib_entry_id}")
    else:
        print("ATTACK FAILED:", result["stopped_reason"])

    # ---- compile the SAME scenario to real Foundry Solidity -------------
    section("STEP 8 — compiling the verified scenario to real Foundry test (.t.sol)")
    compiler = ScenarioCompiler(target_types={"vault": "IVault"})
    out_path = compiler.compile_to_file(
        scenario,
        out_dir=ROOT / "contracts/test/generated",
        attacker_contract_name="MaliciousReceiver_demo",
        attacker_import_path="../../src/attackers/MaliciousReceiver_demo.sol",
    )
    print(f"written: {out_path.relative_to(ROOT)}")
    print(f"(compile only: forge build {out_path.relative_to(ROOT)})")
    validate_rendered_contract(out_path)

    # ---- re-run the IDENTICAL scenario against the PATCHED contract -----
    section("STEP 9 — re-running the identical scenario against SafeVault (patched)")
    safe_executor = MockExecutor(contract_kinds={"vault": "SafeVault", "attacker": "ReentrantAttacker"})
    safe_result = safe_executor.execute(scenario)
    safe_verdict = verifier.verify(scenario, safe_result)
    print(f"reverted={safe_result.reverted}  revert_reason={safe_result.revert_reason!r}")
    print(f"verified={safe_verdict.verified}  (expected: False — the fix holds)")
    validate_demo_outcomes(result, safe_result, safe_verdict)

    # ---- generate a DeFiAudit-style finding from the verified proof -----
    if result["final_proof"]:
        section("STEP 10 — generating audit finding (DeFiAudit integration)")
        from shadow_strike.reporting.report_generator import generate_finding_markdown
        finding_md = generate_finding_markdown(result["final_proof"], finding_id="SS-DEMO-001")
        report_path = ROOT / "contracts/test/generated/SS-DEMO-001-finding.md"
        report_path.write_text(finding_md, encoding="utf-8")
        print(f"written: {report_path.relative_to(ROOT)}")
        print(finding_md[:600] + "\n...")

    store.close()
    section("DONE")
    print(f"Knowledge Store written to: {ROOT / 'shadow_strike_knowledge.sqlite3'}")


if __name__ == "__main__":
    main()
