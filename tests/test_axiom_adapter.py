"""Live proof of the Axiom/Sentinel integration boundary — both the
targeted-class and full-benchmark call paths."""
from __future__ import annotations

import unittest

from shadow_strike.execution.mock_executor import MockExecutor
from shadow_strike.integrations.axiom_adapter import SentinelHypothesisRequest, handle_sentinel_request

SOURCE = """
contract SentinelTestVault {
    mapping(address => uint256) deposits;
    function deposit() external payable { deposits[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amount = deposits[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        deposits[msg.sender] = 0;
    }
}
"""


class TestAxiomAdapter(unittest.TestCase):
    def setUp(self):
        self.executors = {"reentrancy": MockExecutor(contract_kinds={"vault": "VulnerableVault", "attacker": "ReentrantAttacker"})}

    def test_targeted_class_request_returns_verified_verdict(self):
        req = SentinelHypothesisRequest(
            request_id="r1", target_protocol="SentinelTestVault", source_code=SOURCE,
            target_contracts={"vault": "0xabc"}, suspected_vulnerability_class="reentrancy",
        )
        resp = handle_sentinel_request(req, self.executors)
        self.assertTrue(resp.verified)
        self.assertEqual(resp.severity, "critical")
        self.assertIsNotNone(resp.scenario_id)
        self.assertIsNotNone(resp.proof_artifact)

    def test_full_benchmark_request_finds_the_same_issue(self):
        req = SentinelHypothesisRequest(
            request_id="r2", target_protocol="SentinelTestVault", source_code=SOURCE,
            target_contracts={"vault": "0xabc"},
        )
        resp = handle_sentinel_request(req, self.executors)
        self.assertTrue(resp.verified)
        self.assertIn({"vulnerability_class": "reentrancy", "status": "exploitable"}, resp.tested_classes)

    def test_no_executor_never_reports_verified(self):
        req = SentinelHypothesisRequest(
            request_id="r3", target_protocol="SentinelTestVault", source_code=SOURCE,
            target_contracts={"vault": "0xabc"}, suspected_vulnerability_class="reentrancy",
        )
        resp = handle_sentinel_request(req, executors={})
        self.assertFalse(resp.verified)

    def test_unbuildable_class_reports_no_builder_not_a_false_verdict(self):
        req = SentinelHypothesisRequest(
            request_id="r4", target_protocol="SentinelTestVault", source_code=SOURCE,
            target_contracts={"vault": "0xabc"}, suspected_vulnerability_class="economic",
        )
        resp = handle_sentinel_request(req, executors={})
        self.assertFalse(resp.verified)
        self.assertEqual(resp.tested_classes[0]["status"], "no_builder")


if __name__ == "__main__":
    unittest.main()
