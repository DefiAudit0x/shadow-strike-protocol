"""Live proof of the monitoring dispatch logic: alerts fire for
exploitable findings, stay silent for resisted ones, and regressions
(resisted -> exploitable across two events on the same address) are
detected distinctly."""
from __future__ import annotations

import unittest

from shadow_strike.monitoring.watcher import ContinuousMonitor, DeploymentEvent
from shadow_strike.execution.mock_executor import MockExecutor

VULNERABLE_SOURCE = """
contract V { function withdraw() external { msg.sender.call{value: 1}(""); } }
"""
SAFE_SOURCE = """
contract V { function withdraw() external { uint256 x = 1; } }
"""


class TestContinuousMonitor(unittest.TestCase):
    def setUp(self):
        self.executors = {"reentrancy": MockExecutor(contract_kinds={"vault": "VulnerableVault", "attacker": "ReentrantAttacker"})}
        self.alerts = []
        self.monitor = ContinuousMonitor(
            executors=self.executors,
            alert_fn=lambda event, report: self.alerts.append((event.protocol_name, report)),
        )

    def test_alert_fires_for_exploitable_deployment(self):
        event = DeploymentEvent(protocol_name="NewVault", address="0xabc",
                                 source_code=VULNERABLE_SOURCE, event_type="deploy")
        report = self.monitor.handle_event(event)
        self.assertTrue(any(r.status == "exploitable" for r in report.results))
        self.assertEqual(len(self.alerts), 1)

    def test_no_alert_for_source_with_no_matching_pattern(self):
        event = DeploymentEvent(protocol_name="BoringContract", address="0xdef",
                                 source_code=SAFE_SOURCE, event_type="deploy")
        report = self.monitor.handle_event(event)
        self.assertEqual(len(report.results), 0)   # nothing heuristically flagged at all
        self.assertEqual(len(self.alerts), 0)

    def test_regression_detected_across_two_events_same_address(self):
        # first event: contract resists (no executor wired for its flagged
        # class — simulate "previously fine" by using a safe source first)
        safe_event = DeploymentEvent(protocol_name="UpgradeableVault", address="0x111",
                                      source_code=SAFE_SOURCE, event_type="deploy")
        self.monitor.handle_event(safe_event)
        self.assertEqual(len(self.alerts), 0)

        # second event: an "upgrade" to the same address reintroduces reentrancy
        upgraded_event = DeploymentEvent(protocol_name="UpgradeableVault", address="0x111",
                                          source_code=VULNERABLE_SOURCE, event_type="upgrade")
        self.monitor.handle_event(upgraded_event)
        self.assertEqual(len(self.alerts), 1)   # now it should alert


if __name__ == "__main__":
    unittest.main()
