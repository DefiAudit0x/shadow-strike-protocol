#!/usr/bin/env python3
"""
shadow_strike.cli
===================
    python -m shadow_strike.cli run --source contracts/src/Vault.sol \\
        --protocol DemoVault --target vault=0x1111... \\
        --fork-url $MAINNET_RPC_URL --fork-block 19000000 \\
        --attacker-eth 1.0 --engine mock

    python -m shadow_strike.cli library           # list attack library classes
    python -m shadow_strike.cli history <scenario_id>   # past attempts from the Knowledge Store
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from shadow_strike.agent.graph_simple import SimpleShadowStrikeGraph
from shadow_strike.attack_library.registry import AttackLibrary
from shadow_strike.execution.mock_executor import MockExecutor
from shadow_strike.verifier.verifier import Verifier
from shadow_strike.storage.db import KnowledgeStore
from shadow_strike.core.scenario_loader import ScenarioFileError, load_scenario_yaml, save_scenario_yaml
from shadow_strike.core.models import AttackScenario


def _parse_kv(pairs: list[str]) -> dict[str, str]:
    out = {}
    for p in pairs:
        if "=" not in p:
            raise SystemExit(f"expected alias=value, got: {p}")
        k, v = p.split("=", 1)
        out[k] = v
    return out


def cmd_run(args):
    source = Path(args.source).read_text()
    target_contracts = _parse_kv(args.target)

    if args.engine == "foundry":
        from shadow_strike.execution.foundry_runner import ForgeRunner
        executor = ForgeRunner(foundry_project_root=Path(args.foundry_root or "."))
    else:
        kinds = _parse_kv(args.mock_kinds) if args.mock_kinds else {
            next(iter(target_contracts)): "VulnerableVault",
            "attacker": "ReentrantAttacker",
        }
        executor = MockExecutor(contract_kinds=kinds)

    store = KnowledgeStore(db_path=args.db)
    graph = SimpleShadowStrikeGraph(
        executor=executor, verifier=Verifier(), library=AttackLibrary(), max_retries=args.max_retries,
    )

    def on_step(label, state):
        print(f"[{label}]", file=sys.stderr)

    result = graph.run(
        target_contract_source=source,
        target_protocol_name=args.protocol,
        fork_url=args.fork_url or "",
        fork_block=args.fork_block or 0,
        target_contracts=target_contracts,
        attacker_initial_eth=args.attacker_eth,
        on_step=on_step,
    )

    scenario = result.get("current_scenario")
    if scenario is not None:
        store.save_scenario(scenario)
        store.save_attempt(
            scenario_id=scenario.scenario_id,
            attempt_number=result["attempt_count"],
            status="success" if result["final_proof"] else "failure",
            failure_reason=None if result["final_proof"] else result["stopped_reason"],
            execution_result=result["execution_result"].to_dict() if result.get("execution_result") else None,
            verifier_result=result["verifier_verdict"].to_dict() if result.get("verifier_verdict") else None,
        )

    if result["final_proof"]:
        print("ATTACK VERIFIED")
        print(json.dumps(result["final_proof"], indent=2, default=str))
        sys.exit(0)
    else:
        print(f"ATTACK NOT VERIFIED: {result['stopped_reason']}")
        sys.exit(1)


def cmd_run_scenario(args):
    """Run a hand-authored YAML scenario — the path for vulnerability
    classes with no automatic planner builder (accounting,
    upgradeability, cross_contract, economic), and for any scenario a
    researcher wants to write and review by hand rather than generate."""
    try:
        scenario = load_scenario_yaml(args.file)
    except ScenarioFileError as e:
        print(f"SCENARIO FILE ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    print(f"loaded scenario {scenario.scenario_id} ({scenario.vulnerability_class.value}) — validated OK",
          file=sys.stderr)

    if args.engine == "foundry":
        from shadow_strike.execution.foundry_runner import ForgeRunner
        from shadow_strike.execution.compiler import ScenarioCompiler
        compiler = ScenarioCompiler()
        test_path = compiler.compile_to_file(scenario, out_dir=Path(args.foundry_root or ".") / "contracts/test/generated")
        print(f"compiled to {test_path}", file=sys.stderr)
        executor = ForgeRunner(foundry_project_root=Path(args.foundry_root or "."))
    else:
        kinds = _parse_kv(args.mock_kinds) if args.mock_kinds else {}
        if not kinds:
            print("ERROR: --mock-kinds alias=ContractClass is required with --engine mock "
                  "(scenario_loader doesn't guess which mock contract models your hand-written scenario)",
                  file=sys.stderr)
            sys.exit(2)
        params = {}
        if args.mock_params:
            for p in args.mock_params:
                alias, kv = p.split(":", 1)
                k, v = kv.split("=", 1)
                try:
                    v = float(v)
                except ValueError:
                    pass
                params.setdefault(alias, {})[k] = v
        executor = MockExecutor(contract_kinds=kinds, contract_params=params)

    result = executor.execute(scenario) if hasattr(executor, "execute") else executor.run(scenario, test_path)
    verdict = Verifier().verify(scenario, result)

    store = KnowledgeStore(db_path=args.db)
    store.save_scenario(scenario)
    store.save_attempt(
        scenario_id=scenario.scenario_id, attempt_number=1,
        status="success" if verdict.verified else "failure",
        failure_reason=None if verdict.verified else "success_conditions not met",
        execution_result=result.to_dict(), verifier_result=verdict.to_dict(),
    )

    print(json.dumps(verdict.proof_artifact, indent=2, default=str))
    sys.exit(0 if verdict.verified else 1)


def cmd_save_scenario(args):
    """Round-trip a stored scenario back out to an editable YAML file."""
    store = KnowledgeStore(db_path=args.db)
    rows = store.attempts_for_scenario(args.scenario_id)
    if not rows:
        print(f"no attempts found for scenario_id={args.scenario_id}", file=sys.stderr)
        sys.exit(1)
    import json as _json
    scenario_row = store.conn.execute(
        "SELECT scenario_json FROM scenarios WHERE id = ?", (args.scenario_id,)
    ).fetchone()
    scenario = AttackScenario.from_json(scenario_row["scenario_json"])
    out_path = save_scenario_yaml(scenario, args.out)
    print(f"written: {out_path}")


def cmd_library(args):
    lib = AttackLibrary()
    for vc in lib.available_classes():
        meta = lib.get(vc)
        has_template = meta.get("attacker_template") is not None
        print(f"{vc:22s} template={'yes' if has_template else 'no (roadmap)':14s} {meta.get('display_name', '')}")


def cmd_history(args):
    store = KnowledgeStore(db_path=args.db)
    rows = store.attempts_for_scenario(args.scenario_id)
    for row in rows:
        print(dict(row))


def main():
    parser = argparse.ArgumentParser(prog="shadow-strike")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="run the full recon->proof pipeline against a contract source")
    p_run.add_argument("--source", required=True, help="path to Solidity source to recon")
    p_run.add_argument("--protocol", required=True)
    p_run.add_argument("--target", action="append", required=True, help="alias=address, repeatable")
    p_run.add_argument("--fork-url", default="")
    p_run.add_argument("--fork-block", type=int, default=0)
    p_run.add_argument("--attacker-eth", type=float, default=1.0)
    p_run.add_argument("--max-retries", type=int, default=3)
    p_run.add_argument("--engine", choices=["mock", "foundry"], default="mock")
    p_run.add_argument("--foundry-root", default=".")
    p_run.add_argument("--mock-kinds", action="append", help="alias=VulnerableVault|SafeVault|ReentrantAttacker")
    p_run.add_argument("--db", default="shadow_strike_knowledge.sqlite3")
    p_run.set_defaults(func=cmd_run)

    p_lib = sub.add_parser("library", help="list attack library vulnerability classes")
    p_lib.set_defaults(func=cmd_library)

    p_hist = sub.add_parser("history", help="show stored attempts for a scenario_id")
    p_hist.add_argument("scenario_id")
    p_hist.add_argument("--db", default="shadow_strike_knowledge.sqlite3")
    p_hist.set_defaults(func=cmd_history)

    p_run_scenario = sub.add_parser(
        "run-scenario",
        help="run a hand-authored YAML scenario (the path for accounting/upgradeability/"
             "cross_contract/economic classes, or any scenario you want to write by hand)",
    )
    p_run_scenario.add_argument("--file", required=True, help="path to a scenario YAML file")
    p_run_scenario.add_argument("--engine", choices=["mock", "foundry"], default="mock")
    p_run_scenario.add_argument("--foundry-root", default=".")
    p_run_scenario.add_argument("--mock-kinds", action="append",
                                 help="alias=ContractClass, repeatable (required with --engine mock)")
    p_run_scenario.add_argument("--mock-params", action="append",
                                 help="alias:key=value, repeatable — extra constructor kwargs for mock contracts")
    p_run_scenario.add_argument("--db", default="shadow_strike_knowledge.sqlite3")
    p_run_scenario.set_defaults(func=cmd_run_scenario)

    p_save_scenario = sub.add_parser(
        "save-scenario",
        help="export a stored scenario back out to an editable YAML file",
    )
    p_save_scenario.add_argument("scenario_id")
    p_save_scenario.add_argument("--out", required=True)
    p_save_scenario.add_argument("--db", default="shadow_strike_knowledge.sqlite3")
    p_save_scenario.set_defaults(func=cmd_save_scenario)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
