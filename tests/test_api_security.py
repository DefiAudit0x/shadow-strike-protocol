"""Regression coverage for API authentication, queuing, and safe defaults."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import Future
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

    def run_payload(self, **overrides):
        return {
            "source_code": "contract Vault {}", "protocol_name": "Vault",
            "target_contracts": {"vault": "0x1111111111111111111111111111111111111111"},
            **overrides,
        }

    def test_stored_evidence_requires_auth_and_redacts_legacy_secrets(self):
        from shadow_strike.storage.db import KnowledgeStore

        evidence = {
            "fork_url": "https://rpc-user:rpc-password@rpc.example/path-token?api_key=query-token",
            "nested": [{"api_key": "old-api-key", "password": "old-password"}],
            "log": "RPC failed: https://rpc.example/path-secret?token=log-secret",
            "safe": "kept",
        }
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "legacy.sqlite3")
            with patch.dict(os.environ, {self.api.DB_PATH_ENV: db_path}):
                store = KnowledgeStore(db_path)
                store.save_attempt("legacy", 1, "failure", evidence["log"], evidence, evidence)
                store.add_library_entry("reentrancy", evidence)
                store.close()

                denied = self.request("GET", "/runs/legacy")
                self.assertEqual(denied.status_code, 401, denied.text)
                for route, field in (
                    ("/runs/legacy", "execution_result_json"),
                    ("/attack-library/reentrancy", "scenario_template_json"),
                ):
                    with self.subTest(route=route):
                        response = self.request("GET", route, headers=self.auth())
                        self.assertEqual(response.status_code, 200, response.text)
                        row = response.json()[0]
                        sanitized = json.loads(row[field])
                        self.assertEqual(sanitized["fork_url"], "[REDACTED]")
                        self.assertEqual(sanitized["safe"], "kept")
                        for secret in ("rpc-password", "path-token", "query-token", "old-api-key",
                                       "old-password", "path-secret", "log-secret"):
                            self.assertNotIn(secret, response.text)

    def test_job_evidence_and_errors_redact_credentials(self):
        for fails in (False, True):
            with self.subTest(fails=fails):
                future = Future()
                if fails:
                    future.set_exception(ValueError("Authorization: Bearer private-token"))
                else:
                    future.set_result({"proof": {"fork_url": "https://user:password@example/token",
                                                 "access_token": "private-token"}})
                with patch.object(self.api, "_jobs", {}), \
                        patch.object(self.api._job_executor, "submit", return_value=future):
                    job = self.api._queue_job(dict)
                    response = self.request("GET", f"/jobs/{job['job_id']}", headers=self.auth())
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.json()["status"], "failed" if fails else "complete")
                self.assertNotIn("private-token", response.text)
                self.assertNotIn("password", response.text)

    def test_job_capacity_rejects_before_submitting_work(self):
        for state in ("pending", "running", "complete", "failed"):
            with self.subTest(state=state):
                future = Future()
                if state == "running":
                    future.set_running_or_notify_cancel()
                elif state == "complete":
                    future.set_result({})
                elif state == "failed":
                    future.set_exception(ValueError("failed"))
                with patch.object(self.api, "_jobs", {}), \
                        patch.object(self.api, "MAX_TRACKED_JOBS", 1), \
                        patch.object(self.api._job_executor, "submit", return_value=future) as submit:
                    first = self.request("POST", "/runs", headers=self.auth(), json=self.run_payload())
                    second = self.request("POST", "/runs", headers=self.auth(), json=self.run_payload())
                    self.assertEqual(first.status_code, 202, first.text)
                    self.assertEqual(second.status_code, 503, second.text)
                    self.assertIn("capacity", second.json()["detail"])
                    self.assertEqual(len(self.api._jobs), 1)
                    submit.assert_called_once()

    def test_terminal_jobs_expire_from_completion_on_access_and_submission(self):
        for fails in (False, True):
            for cleanup in ("access", "submission"):
                with self.subTest(fails=fails, cleanup=cleanup):
                    future = Future()
                    with patch.object(self.api, "_jobs", {}), \
                            patch.object(self.api, "MAX_TRACKED_JOBS", 1), \
                            patch.object(self.api, "monotonic", return_value=0) as clock, \
                            patch.object(self.api._job_executor, "submit", return_value=future):
                        job = self.api._queue_job(dict)
                        clock.return_value = self.api.JOB_RETENTION_SECONDS * 2
                        active = self.request("GET", f"/jobs/{job['job_id']}", headers=self.auth())
                        self.assertEqual(active.status_code, 200, active.text)
                        if fails:
                            future.set_exception(ValueError("failed"))
                        else:
                            future.set_result({"ok": True})
                        clock.return_value += self.api.JOB_RETENTION_SECONDS - 1
                        self.assertEqual(self.poll(job["job_id"])["status"], "failed" if fails else "complete")
                        clock.return_value += 1
                        if cleanup == "submission":
                            replacement = self.request("POST", "/runs", headers=self.auth(), json=self.run_payload())
                            self.assertEqual(replacement.status_code, 202, replacement.text)
                        expired = self.request("GET", f"/jobs/{job['job_id']}", headers=self.auth())
                        self.assertEqual(expired.status_code, 404, expired.text)
                        self.assertNotIn(job["job_id"], self.api._jobs)

    def test_unknown_engine_rejected_without_queuing(self):
        with patch.object(self.api, "_queue_job") as queue:
            response = self.request("POST", "/runs", headers=self.auth(),
                                    json=self.run_payload(engine="foudnry"))
        self.assertEqual(response.status_code, 422, response.text)
        queue.assert_not_called()

    def test_job_result_reports_selected_engine(self):
        for engine in ("mock", "foundry"):
            with self.subTest(engine=engine), \
                    patch.object(self.api, "SimpleShadowStrikeGraph") as graph, \
                    patch.object(self.api, "MockExecutor") as mock_executor, \
                    patch("shadow_strike.execution.foundry_runner.ForgeRunner") as foundry_executor:
                graph.return_value.run.return_value = {
                    "current_scenario": None, "stopped_reason": "done", "final_proof": None, "history": [],
                }
                response = self.request("POST", "/runs", headers=self.auth(), json=self.run_payload(engine=engine))
                self.assertEqual(response.status_code, 202, response.text)
                completed = self.poll(response.json()["job_id"])
                self.assertEqual(completed["status"], "complete")
                self.assertEqual(completed["result"]["engine"], engine)
                selected = mock_executor if engine == "mock" else foundry_executor
                unused = foundry_executor if engine == "mock" else mock_executor
                selected.assert_called_once()
                unused.assert_not_called()
                self.assertIs(graph.call_args.kwargs["executor"], selected.return_value)

    def test_schema_bounds_reject_invalid_requests_before_queuing(self):
        for route in ("/runs", "/benchmark", "/sentinel/hypothesis"):
            invalid = {"target_contracts": {}, "fork_block": -1, "attacker_initial_eth": -1}
            if route == "/runs":
                invalid["max_retries"] = -1
            for field, value in invalid.items():
                with self.subTest(route=route, field=field), patch.object(self.api, "_queue_job") as queue:
                    payload = self.run_payload(**{field: value})
                    if route == "/sentinel/hypothesis":
                        payload.update(request_id="r", target_protocol="Vault")
                    response = self.request("POST", route, headers=self.auth(), json=payload)
                    self.assertEqual(response.status_code, 422, response.text)
                    queue.assert_not_called()

    def test_schema_zero_boundaries_are_accepted(self):
        for route in ("/runs", "/benchmark", "/sentinel/hypothesis"):
            with self.subTest(route=route), patch.object(self.api, "_queue_job", return_value={"job_id": "j"}) as queue:
                payload = self.run_payload(fork_block=0, attacker_initial_eth=0, max_retries=0)
                if route == "/sentinel/hypothesis":
                    payload.update(request_id="r", target_protocol="Vault")
                response = self.request("POST", route, headers=self.auth(), json=payload)
                self.assertEqual(response.status_code, 202, response.text)
                queue.assert_called_once()

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
