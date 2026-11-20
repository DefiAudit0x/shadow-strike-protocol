"""Live proof the benchmark runner correctly scores a contract with
TWO independent vulnerability classes in one pass."""
from __future__ import annotations

import unittest

from shadow_strike.benchmark.runner import run_benchmark
from shadow_strike.execution.mock_executor import MockExecutor

MULTI_VULN_SOURCE = """
contract MultiVulnDemo {
    address owner;
    mapping(address => uint256) deposits;
    function deposit() external payable { deposits[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amount = deposits[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        deposits[msg.sender] = 0;
    }
    function adminAction() external {
        require(tx.origin == owner, "not owner");
    }
}
"""


class TestBenchmarkRunner(unittest.TestCase):
    def test_scores_both_vulnerability_classes_independently(self):
        executors = {
            "reentrancy": MockExecutor(contract_kinds={"vault": "VulnerableVault", "attacker": "ReentrantAttacker"}),
            "access_control": MockExecutor(contract_kinds={"vault": "AccessControlTarget"},
                                            contract_params={"vault": {"owner": "deployer", "enforce_check": True}}),
        }
        report = run_benchmark(
            target_contract_source=MULTI_VULN_SOURCE,
            target_protocol_name="MultiVulnDemo",
            target_contracts={"vault": "0xabc"},
            executors=executors,
        )
        by_class = {r.vulnerability_class: r.status for r in report.results}
        self.assertEqual(by_class["reentrancy"], "exploitable")
        self.assertEqual(by_class["access_control"], "resisted")

    def test_missing_executor_reports_skipped_not_failed(self):
        report = run_benchmark(
            target_contract_source=MULTI_VULN_SOURCE,
            target_protocol_name="MultiVulnDemo",
            target_contracts={"vault": "0xabc"},
            executors={},  # nothing configured
        )
        statuses = {r.status for r in report.results}
        self.assertEqual({r.vulnerability_class for r in report.results}, {"reentrancy", "access_control"})
        self.assertEqual(statuses, {"no_executor"})

    def test_scorecard_is_nonempty_string(self):
        report = run_benchmark(
            target_contract_source=MULTI_VULN_SOURCE,
            target_protocol_name="MultiVulnDemo",
            target_contracts={"vault": "0xabc"},
            executors={},
        )
        self.assertIn("MultiVulnDemo", report.scorecard())


if __name__ == "__main__":
    unittest.main()
