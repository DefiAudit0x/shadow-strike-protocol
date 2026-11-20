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
import ast
import json
import re
import sys
from pathlib import Path

from shadow_strike.agent.graph_simple import SimpleShadowStrikeGraph
from shadow_strike.agent.llm_providers import LLMProviderError, build_llm_fn
from shadow_strike.attack_library.registry import AttackLibrary
from shadow_strike.core.models import AttackScenario
from shadow_strike.core.scenario_loader import ScenarioFileError, load_scenario_yaml, save_scenario_yaml
from shadow_strike.execution.mock_executor import MockExecutor
from shadow_strike.storage.persistence import run_store, save_run
from shadow_strike.verifier.verifier import Verifier


def _parse_kv(pairs: list[str]) -> dict[str, str]:
    out = {}
    for p in pairs:
        if "=" not in p:
            raise SystemExit(f"expected alias=value, got: {p}")
        k, v = p.split("=", 1)
        out[k] = v
    return out


def _parse_mock_params(pairs: list[str]) -> dict[str, dict]:
    params = {}
    for pair in pairs:
        name, equals, raw = pair.partition("=")
        alias, colon, key = name.partition(":")
        value = raw.strip()
        if not (equals and colon and alias and key and value) or re.search(r"[\s:]", alias + key):
            raise ValueError(f"expected alias:key=value, got {pair!r}")

        lowered = value.lower()
        if lowered in {"true", "false"}:
            parsed = lowered == "true"
        elif lowered in {"null", "none"}:
            parsed = None
        elif value.startswith(("'", '"')):
            try:
                parsed = ast.literal_eval(value)
                if not isinstance(parsed, str):
                    raise TypeError("expected a quoted string")
            except (SyntaxError, TypeError, ValueError) as exc:
                raise ValueError(f"invalid quoted value {value!r} in {pair!r}") from exc
        elif re.fullmatch(r"[+-]?[0-9]+", value):
            try:
                parsed = int(value)
            except ValueError as exc:
                raise ValueError(f"invalid integer value {value!r} in {pair!r}") from exc
        elif re.fullmatch(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", value):
            parsed = float(value)
        else:
            parsed = raw
        params.setdefault(alias, {})[key] = parsed
    return params


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

    try:
        llm_fn = build_llm_fn(
            getattr(args, "llm_provider", None), getattr(args, "llm_api_key", None),
        )
    except LLMProviderError as e:
        print(f"LLM ERROR: {e}", file=sys.stderr)
        sys.exit(2)
    graph = SimpleShadowStrikeGraph(
        executor=executor, verifier=Verifier(), library=AttackLibrary(), max_retries=args.max_retries,
        llm_fn=llm_fn,
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
        with run_store(db_path=args.db) as store:
            save_run(
                store, scenario, result.get("execution_result"), result.get("verifier_verdict"),
                attempt_number=result["attempt_count"], failure_reason=result["stopped_reason"],
                attempts=result.get("attempt_records"),
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
        from shadow_strike.execution.compiler import ScenarioCompiler
        from shadow_strike.execution.foundry_runner import ForgeRunner
        # The bundled attacker and interface implement the reentrancy demo.
        is_reentrancy = scenario.vulnerability_class.value == "reentrancy"
        primary_target = next(iter(scenario.initial_state.target_contracts))
        compiler = ScenarioCompiler(target_types={primary_target: "IVault"} if is_reentrancy else None)
        test_path = compiler.compile_to_file(
            scenario,
            out_dir=Path(args.foundry_root or ".") / "contracts/test/generated",
            attacker_contract_name="MaliciousReceiver_demo" if is_reentrancy else None,
        )
        print(f"compiled to {test_path}", file=sys.stderr)
        executor = ForgeRunner(foundry_project_root=Path(args.foundry_root or "."))
    else:
        kinds = _parse_kv(args.mock_kinds) if args.mock_kinds else {}
        if not kinds:
            print("ERROR: --mock-kinds alias=ContractClass is required with --engine mock "
                  "(scenario_loader doesn't guess which mock contract models your hand-written scenario)",
                  file=sys.stderr)
            sys.exit(2)
        try:
            params = _parse_mock_params(args.mock_params or [])
        except ValueError as e:
            print(f"MOCK PARAM ERROR: {e}", file=sys.stderr)
            sys.exit(2)
        executor = MockExecutor(contract_kinds=kinds, contract_params=params)

    result = executor.execute(scenario) if hasattr(executor, "execute") else executor.run(scenario, test_path)
    verdict = Verifier().verify(scenario, result)

    with run_store(db_path=args.db) as store:
        save_run(store, scenario, result, verdict, failure_reason="success_conditions not met")

    print(json.dumps(verdict.proof_artifact, indent=2, default=str))
    sys.exit(0 if verdict.verified else 1)


def cmd_save_scenario(args):
    """Round-trip a stored scenario back out to an editable YAML file."""
    with run_store(db_path=args.db) as store:
        scenario_row = store.get_scenario(args.scenario_id)
        if scenario_row is None:
            print(f"ERROR: scenario not found: {args.scenario_id}", file=sys.stderr)
            sys.exit(1)
        scenario = AttackScenario.from_json(scenario_row["scenario_json"])
    out_path = save_scenario_yaml(scenario, args.out)
    print(f"written: {out_path}")


def cmd_library(args):
    lib = AttackLibrary()
    for vc in lib.available_classes():
        meta = lib.get(vc)
        print(f"{vc:22s} {meta.get('display_name', '')}")


def cmd_history(args):
    with run_store(db_path=args.db) as store:
        for row in store.attempts_for_scenario(args.scenario_id):
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
    # Part 10: the LLM proposes hypotheses; the deterministic verifier
    # still decides the verdict. "echo" is the offline test double.
    p_run.add_argument("--llm-provider", choices=["anthropic", "echo"], default=None,
                       help="LLM provider for hypothesis generation (default: heuristics only)")
    p_run.add_argument("--llm-api-key", default=None,
                       help="Anthropic API key (or set ANTHROPIC_API_KEY)")
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
