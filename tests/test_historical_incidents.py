"""Live proof the three historical-incident YAML reconstructions load
and verify through the real pipeline — see examples/historical_incidents/
README.md for the honesty caveats on historical accuracy."""
from __future__ import annotations

import unittest
from pathlib import Path

from shadow_strike.core.scenario_loader import load_scenario_yaml
from shadow_strike.execution.mock_executor import MockExecutor
from shadow_strike.verifier.verifier import Verifier

HERE = Path(__file__).parent.parent / "examples" / "historical_incidents"


class TestHistoricalIncidents(unittest.TestCase):
    def test_the_dao_reentrancy_verifies(self):
        scenario = load_scenario_yaml(HERE / "the_dao_2016_reentrancy.yaml")
        executor = MockExecutor(contract_kinds={"vault": "VulnerableVault", "attacker": "ReentrantAttacker"})
        verdict = Verifier().verify(scenario, executor.execute(scenario))
        self.assertTrue(verdict.verified)

    def test_parity_initialization_verifies(self):
        scenario = load_scenario_yaml(HERE / "parity_wallet_2017_initialization.yaml")
        executor = MockExecutor(contract_kinds={"vault": "InitializableTarget"})
        verdict = Verifier().verify(scenario, executor.execute(scenario))
        self.assertTrue(verdict.verified)

    def test_mango_oracle_manipulation_verifies(self):
        scenario = load_scenario_yaml(HERE / "mango_markets_2022_oracle_manipulation.yaml")
        executor = MockExecutor(
            contract_kinds={"pool": "SimplePool", "market": "OracleFedLendingMarket", "attacker": "OracleManipulationAttacker"},
            contract_params={
                "pool": {"reserve_a": 80.0, "reserve_b": 80.0},
                "market": {"pool_alias": "pool", "reserve_eth": 150.0},
                "attacker": {"pool_alias": "pool", "market_alias": "market"},
            },
        )
        verdict = Verifier().verify(scenario, executor.execute(scenario))
        self.assertTrue(verdict.verified)


if __name__ == "__main__":
    unittest.main()
