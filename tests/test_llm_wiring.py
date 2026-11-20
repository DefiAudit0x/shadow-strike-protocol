"""Part 10 tests — the LLM is wired into the CLI/API and its output
actually becomes hypotheses (and a failing provider degrades to
heuristics instead of crashing the run).
"""
from __future__ import annotations

import asyncio
import importlib.util
import os
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from shadow_strike.agent.graph_simple import SimpleShadowStrikeGraph
from shadow_strike.agent.llm_providers import (
    EchoLLM,
    LLMProviderError,
    build_llm_fn,
)
from shadow_strike.agent.nodes import hypothesis_node
from shadow_strike.attack_library.registry import AttackLibrary
from shadow_strike.execution.mock_executor import MockExecutor
from shadow_strike.verifier.verifier import Verifier

_SOURCE = """
contract Vault {
    function withdraw() external {
        (bool ok,) = msg.sender.call{value: 1}("");
    }
}
"""


def _run_graph(llm_fn, kinds=None, max_retries=3):
    kinds = kinds or {"vault": "VulnerableVault", "attacker": "ReentrantAttacker"}
    graph = SimpleShadowStrikeGraph(
        executor=MockExecutor(contract_kinds=kinds), verifier=Verifier(),
        library=AttackLibrary(), max_retries=max_retries, llm_fn=llm_fn,
    )
    return graph.run(
        target_contract_source=_SOURCE,
        target_protocol_name="InlineTestVault",
        fork_url="", fork_block=0,
        target_contracts={"vault": "0xdead"},
        attacker_initial_eth=1.0,
    )


class TestLLMHypothesisWiring(unittest.TestCase):
    def test_echo_llm_hypothesis_reaches_planner(self):
        # EchoLLM returns the prompt's last line — the format example in
        # hypothesis_node's prompt — which the parser turns into a real
        # reentrancy hypothesis sitting in the list the planner reads.
        result = _run_graph(EchoLLM())
        llm_hypotheses = [
            h for h in result["hypotheses"] if "LLM-proposed" in h.get("confidence_note", "")
        ]
        self.assertTrue(llm_hypotheses, "no LLM-proposed hypothesis reached the planner")
        self.assertEqual(llm_hypotheses[0]["vulnerability_class"], "reentrancy")
        self.assertEqual(result["stopped_reason"], "verified")

    def test_llm_hypothesis_lines_are_parsed(self):
        def fake_llm(prompt):
            return (
                "access_control: initialize() can be called by anyone.\n"
                "reentrancy: withdraw() sends ETH before updating the balance.\n"
                "this line names no known class and must be ignored\n"
                "economic: \n"
            )

        state = {"target_contract_source": _SOURCE, "recon_notes": "recon"}
        out = hypothesis_node(state, llm_fn=fake_llm, library=AttackLibrary())
        parsed = [h for h in out["hypotheses"] if "LLM-proposed" in h["confidence_note"]]
        self.assertEqual(
            [(h["vulnerability_class"], h["hypothesis"]) for h in parsed],
            [
                ("access_control", "initialize() can be called by anyone."),
                ("reentrancy", "withdraw() sends ETH before updating the balance."),
            ],
        )

    def test_raising_llm_degrades_to_heuristics(self):
        def boom(prompt):
            raise RuntimeError("provider down")

        result = _run_graph(boom)
        # The run completes instead of crashing, with heuristic hypotheses.
        self.assertTrue(result["hypotheses"])
        self.assertFalse(any(
            "LLM-proposed" in h.get("confidence_note", "") for h in result["hypotheses"]
        ))
        self.assertEqual(result["stopped_reason"], "verified")


class TestBuildLLMFn(unittest.TestCase):
    def test_none_means_heuristics_only(self):
        self.assertIsNone(build_llm_fn(None))

    def test_echo_returns_test_double(self):
        self.assertIsInstance(build_llm_fn("echo"), EchoLLM)

    def test_anthropic_without_key_raises(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ANTHROPIC_API_KEY", None)
            with self.assertRaises(LLMProviderError):
                build_llm_fn("anthropic")

    def test_unknown_provider_raises(self):
        with self.assertRaises(ValueError):
            build_llm_fn("bogus")


class TestCLIAndAPIWiring(unittest.TestCase):
    def test_cli_run_accepts_llm_provider_echo(self):
        from shadow_strike.cli import cmd_run

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "Vault.sol"
            src.write_text(_SOURCE)
            args = Namespace(
                source=str(src), protocol="InlineTestVault", target=["vault=0xdead"],
                fork_url="", fork_block=0, attacker_eth=1.0, max_retries=3,
                engine="mock", foundry_root=".", mock_kinds=None,
                db=str(Path(tmp) / "test.sqlite3"),
                llm_provider="echo", llm_api_key=None,
            )
            with self.assertRaises(SystemExit) as ctx:
                cmd_run(args)
            self.assertEqual(ctx.exception.code, 0)  # ATTACK VERIFIED

    @unittest.skipUnless(
        importlib.util.find_spec("fastapi") and importlib.util.find_spec("httpx"),
        "API regression requires optional fastapi and httpx dependencies",
    )
    def test_api_run_accepts_llm_field(self):
        import httpx

        from shadow_strike.api import main as api

        with tempfile.TemporaryDirectory() as tmp:
            token = "llm-wiring-test"
            async def run_api_job():
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=api.app), base_url="http://test",
                ) as client:
                    response = await client.post("/runs", json={
                        "source_code": _SOURCE, "protocol_name": "LLM API",
                        "target_contracts": {"vault": "0xdead"},
                        "engine": "mock", "max_retries": 3, "llm": "echo",
                    }, headers={"Authorization": f"Bearer {token}"})
                    self.assertEqual(response.status_code, 202, response.text)
                    job_id = response.json()["job_id"]
                    for _ in range(100):
                        status = await client.get(
                            f"/jobs/{job_id}", headers={"Authorization": f"Bearer {token}"},
                        )
                        self.assertEqual(status.status_code, 200, status.text)
                        if status.json()["status"] in ("complete", "failed"):
                            break
                        await asyncio.sleep(0.01)
                    self.assertEqual(status.json()["status"], "complete", status.text)
                    self.assertTrue(status.json()["result"]["verified"])

            with patch.dict(os.environ, {
                "SHADOW_STRIKE_API_TOKEN": token,
                "SHADOW_STRIKE_DB_PATH": str(Path(tmp) / "api.sqlite3"),
            }):
                asyncio.run(run_api_job())

    def test_api_rejects_unknown_llm_provider(self):
        from pydantic import ValidationError

        from shadow_strike.api.main import RunRequest

        with self.assertRaises(ValidationError):
            RunRequest(
                source_code=_SOURCE, protocol_name="x",
                target_contracts={"vault": "0xdead"}, llm="bogus",
            )


if __name__ == "__main__":
    unittest.main()
