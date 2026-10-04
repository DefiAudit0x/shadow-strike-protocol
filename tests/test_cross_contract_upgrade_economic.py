"""Live proof of the three remaining roadmap classes' hand-authoring
path: cross_contract (trust hijack), upgradeability (storage collision),
economic (profitable self-liquidation). None of these have an automated
scenario_planner builder, by design — see each attack_library meta.yaml."""
from __future__ import annotations

import unittest
from pathlib import Path

from shadow_strike.core.scenario_loader import load_scenario_yaml
from shadow_strike.execution.mock_executor import MockExecutor
from shadow_strike.verifier.verifier import Verifier

SCENARIOS_DIR = Path(__file__).parent.parent / "examples" / "scenarios"


class TestCrossContractTrustHijack(unittest.TestCase):
    def test_attacker_hijacks_trust_and_drains_router(self):
        scenario = load_scenario_yaml(SCENARIOS_DIR / "cross_contract_trust_hijack_demo.yaml")
        executor = MockExecutor(contract_kinds={
            "router": "TrustingRouter", "legitimate_computer": "LegitimateComputer", "malicious_computer": "MaliciousComputer",
        })
        verdict = Verifier().verify(scenario, executor.execute(scenario))
        self.assertTrue(verdict.verified)

    def test_router_without_the_bug_would_stay_on_legitimate_computer(self):
        # sanity check: the legitimate computer alone caps authorization —
        # confirms the exploit specifically needs the trust redirection
        scenario = load_scenario_yaml(SCENARIOS_DIR / "cross_contract_trust_hijack_demo.yaml")
        scenario.steps = [scenario.steps[1]]  # skip the setTrustedComputer hijack step
        executor = MockExecutor(contract_kinds={
            "router": "TrustingRouter", "legitimate_computer": "LegitimateComputer", "malicious_computer": "MaliciousComputer",
        }, contract_params={"legitimate_computer": {"cap": 1.0}})
        result = executor.execute(scenario)
        self.assertTrue(result.reverted)   # 50.0 requested > legitimate computer's 1.0 cap


class TestUpgradeabilityStorageCollision(unittest.TestCase):
    def test_malicious_implementation_hijacks_ownership(self):
        scenario = load_scenario_yaml(SCENARIOS_DIR / "upgradeability_storage_collision_demo.yaml")
        executor = MockExecutor(contract_kinds={"proxy": "VulnerableProxy", "malicious_impl": "MaliciousImplementation"})
        verdict = Verifier().verify(scenario, executor.execute(scenario))
        self.assertTrue(verdict.verified)


class TestEconomicSelfLiquidation(unittest.TestCase):
    def test_generous_bonus_makes_self_liquidation_profitable(self):
        scenario = load_scenario_yaml(SCENARIOS_DIR / "economic_self_liquidation_demo.yaml")
        executor = MockExecutor(contract_kinds={"market": "SelfLiquidationMarket"},
                                 contract_params={"market": {"liquidation_bonus_bps": 2000.0}})
        verdict = Verifier().verify(scenario, executor.execute(scenario))
        self.assertTrue(verdict.verified)

    def test_conservative_bonus_makes_self_liquidation_unprofitable(self):
        scenario = load_scenario_yaml(SCENARIOS_DIR / "economic_self_liquidation_demo.yaml")
        executor = MockExecutor(contract_kinds={"market": "SelfLiquidationMarket"},
                                 contract_params={"market": {"liquidation_bonus_bps": 500.0}})
        verdict = Verifier().verify(scenario, executor.execute(scenario))
        self.assertFalse(verdict.verified)


if __name__ == "__main__":
    unittest.main()
