"""Regression coverage for API authentication, queuing, and safe defaults."""

from __future__ import annotations

import asyncio
import importlib.util
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HAS_API_TEST_DEPS = bool(importlib.util.find_spec("fastapi") and importlib.util.find_spec("httpx"))


@unittest.skipUnless(HAS_API_TEST_DEPS, "API regression requires optional fastapi and httpx dependencies")
class TestAPISecurity(unittest.TestCase):
    def setUp(self):
        from shadow_strike.api import main as api

        self.api = api
        self.env = patch.dict(os.environ, {api.API_TOKEN_ENV: "unit-test-secret"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def request(self, method, path, **kwargs):
        import httpx

        async def send():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=self.api.app), base_url="http://test",
            ) as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(send())

    def auth(self):
        return {"Authorization": "Bearer unit-test-secret"}

    def poll(self, job_id):
        for _ in range(100):
            response = self.request("GET", f"/jobs/{job_id}", headers=self.auth())
            self.assertEqual(response.status_code, 200, response.text)
            result = response.json()
            if result["status"] in ("complete", "failed"):
                return result
            time.sleep(0.01)
        self.fail("queued API job did not finish")

    def test_mutating_routes_require_bearer_token(self):
        requests = (
            ("/runs", {"source_code": "", "protocol_name": "x", "target_contracts": {"vault": "0x1"}}),
            ("/benchmark", {"source_code": "", "protocol_name": "x", "target_contracts": {"vault": "0x1"}}),
            ("/sentinel/hypothesis", {
                "request_id": "r", "target_protocol": "x", "source_code": "",
                "target_contracts": {"vault": "0x1"},
            }),
        )
        for route, payload in requests:
            with self.subTest(route=route):
                response = self.request("POST", route, json=payload)
                self.assertEqual(response.status_code, 401, response.text)

    def test_fork_url_rejected_before_forge_invocation(self):
        from shadow_strike.execution.foundry_runner import ForgeRunner

        with patch.object(ForgeRunner, "__init__", side_effect=AssertionError("forge should not start")) as init:
            response = self.request("POST", "/runs", headers=self.auth(), json={
                "source_code": "contract Vault {}", "protocol_name": "Vault",
                "target_contracts": {"vault": "0x1111111111111111111111111111111111111111"},
                "engine": "foundry", "fork_url": "https://not-allowed.example/rpc",
            })
        self.assertEqual(response.status_code, 400, response.text)
        init.assert_not_called()

    def test_run_is_queued_and_job_can_be_polled(self):
        with patch.object(self.api, "_execute_run", return_value={"verified": False, "scenario_id": "s"}):
            response = self.request("POST", "/runs", headers=self.auth(), json={
                "source_code": "contract Vault {}", "protocol_name": "Vault",
                "target_contracts": {"vault": "0x1111111111111111111111111111111111111111"},
            })
            self.assertEqual(response.status_code, 202, response.text)
            body = response.json()
            self.assertTrue(body["job_id"])
            self.assertEqual(body["status"], "queued")
            completed = self.poll(body["job_id"])
        self.assertEqual(completed["status"], "complete")
        self.assertEqual(completed["result"]["scenario_id"], "s")

    def test_attack_library_hides_internal_paths(self):
        response = self.request("GET", "/attack-library")
        self.assertEqual(response.status_code, 200)
        for entry in response.json():
            self.assertNotIn("_dir", entry)
            self.assertFalse(any(
                isinstance(value, str) and str(ROOT) in value
                for value in entry.values()
            ))

    def test_websocket_stub_is_removed(self):
        self.assertFalse(any(
            getattr(route, "path", None) == "/runs/{scenario_id}/stream"
            for route in self.api.app.routes
        ))


class TestAPILazyStoreImport(unittest.TestCase):
    @unittest.skipUnless(HAS_API_TEST_DEPS, "API regression requires optional fastapi dependencies")
    def test_import_does_not_create_sqlite_file_in_working_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            env = os.environ.copy()
            env["PYTHONPATH"] = str(ROOT)
            result = subprocess.run(
                [sys.executable, "-c", "import shadow_strike.api.main"],
                cwd=directory,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(list(Path(directory).glob("*.sqlite*")), [])


if __name__ == "__main__":
    unittest.main()
