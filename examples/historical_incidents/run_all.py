#!/usr/bin/env python3
"""Replays the three historical incident reconstructions in this folder
against the mock engine and prints a verdict + audit finding for each.
See README.md in this folder for the honesty caveats before treating
any of this as historically rigorous."""
from __future__ import annotations

from pathlib import Path

from shadow_strike.core.scenario_loader import load_scenario_yaml
from shadow_strike.execution.mock_executor import MockExecutor
from shadow_strike.verifier.verifier import Verifier
from shadow_strike.reporting.report_generator import generate_finding_markdown

HERE = Path(__file__).parent

INCIDENTS = [
    ("the_dao_2016_reentrancy.yaml",
     MockExecutor(contract_kinds={"vault": "VulnerableVault", "attacker": "ReentrantAttacker"})),
    ("parity_wallet_2017_initialization.yaml",
     MockExecutor(contract_kinds={"vault": "InitializableTarget"})),
    ("mango_markets_2022_oracle_manipulation.yaml",
     MockExecutor(
         contract_kinds={"pool": "SimplePool", "market": "OracleFedLendingMarket", "attacker": "OracleManipulationAttacker"},
         contract_params={
             "pool": {"reserve_a": 80.0, "reserve_b": 80.0},   # thin market — the actual exploited condition
             "market": {"pool_alias": "pool", "reserve_eth": 150.0},
             "attacker": {"pool_alias": "pool", "market_alias": "market"},
         },
     )),
]


def main():
    verifier = Verifier()
    for filename, executor in INCIDENTS:
        path = HERE / filename
        scenario = load_scenario_yaml(path)
        print("=" * 70)
        print(f"{filename}  [{scenario.vulnerability_class.value}]")
        print("=" * 70)

        result = executor.execute(scenario)
        verdict = verifier.verify(scenario, result)

        print(f"reverted={result.reverted}  revert_reason={result.revert_reason}")
        print(f"VERDICT: {'ATTACK VERIFIED ✔' if verdict.verified else 'ATTACK NOT VERIFIED'}")

        if verdict.verified:
            finding = generate_finding_markdown(verdict.proof_artifact, finding_id=filename.split('.')[0].upper())
            out_path = HERE / f"{path.stem}-finding.md"
            out_path.write_text(finding, encoding="utf-8")
            print(f"finding written: {out_path.name}")
        print()


if __name__ == "__main__":
    main()
