from __future__ import annotations

import importlib.util
import shutil
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

DEMO_PATH = Path(__file__).parent.parent / "examples" / "run_demo.py"
spec = importlib.util.spec_from_file_location("run_demo", DEMO_PATH)
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


class TestDemoAcceptance(unittest.TestCase):
    def test_swapped_safe_target_fails_acceptance_gate(self):
        positive_verdict = SimpleNamespace(verified=True)
        result = {"final_proof": {"proof": True}, "verifier_verdict": positive_verdict}
        safe_result = SimpleNamespace(reverted=False, revert_reason=None)
        with self.assertRaisesRegex(RuntimeError, "negative control unexpectedly verified"):
            demo.validate_demo_outcomes(result, safe_result, SimpleNamespace(verified=True))

    def test_positive_control_failure_fails_acceptance_gate(self):
        result = {"final_proof": None, "verifier_verdict": SimpleNamespace(verified=False)}
        safe_result = SimpleNamespace(reverted=False, revert_reason=None)
        with self.assertRaisesRegex(RuntimeError, "positive control did not produce verified evidence"):
            demo.validate_demo_outcomes(result, safe_result, SimpleNamespace(verified=False))

    def test_errored_negative_control_fails_acceptance_gate(self):
        result = {"final_proof": {"proof": True}, "verifier_verdict": SimpleNamespace(verified=True)}
        safe_result = SimpleNamespace(reverted=True, revert_reason="execution reverted")
        with self.assertRaisesRegex(RuntimeError, "negative control execution errored"):
            demo.validate_demo_outcomes(result, safe_result, SimpleNamespace(verified=False))

    def test_error_verdict_fails_acceptance_gate(self):
        result = {"final_proof": {"proof": True}, "verifier_verdict": SimpleNamespace(verified=True)}
        safe_result = SimpleNamespace(reverted=False, revert_reason=None)
        with self.assertRaisesRegex(RuntimeError, "negative control verdict was not 'resisted'"):
            demo.validate_demo_outcomes(result, safe_result, SimpleNamespace(verified=False, verdict="error"))

    def test_inconclusive_verdict_fails_acceptance_gate(self):
        result = {"final_proof": {"proof": True}, "verifier_verdict": SimpleNamespace(verified=True)}
        safe_result = SimpleNamespace(reverted=False, revert_reason=None)
        with self.assertRaisesRegex(RuntimeError, "negative control verdict was not 'resisted'"):
            demo.validate_demo_outcomes(result, safe_result, SimpleNamespace(verified=False, verdict="inconclusive"))

    @unittest.skipUnless(shutil.which("forge"), "forge not on PATH")
    def test_invalid_rendered_solidity_fails_real_compiler_gate(self):
        # The X02 mutation, for real: garbage in place of the emitted
        # contract must make the compiler gate fail (not just a mock).
        generated = Path(__file__).parent.parent / "contracts" / "test" / "generated"
        # contracts/test/generated is gitignored: a clean checkout has no
        # such directory, so create it before writing the fixture.
        existed = generated.exists()
        generated.mkdir(parents=True, exist_ok=True)
        garbage = generated / "ZZInvalidGate.t.sol"
        garbage.write_text("THIS IS NOT SOLIDITY\n", encoding="utf-8")
        try:
            with self.assertRaisesRegex(RuntimeError, "forge build failed"):
                demo.validate_rendered_contract(garbage)
        finally:
            garbage.unlink(missing_ok=True)
            if not existed:
                try:
                    generated.rmdir()
                except OSError:
                    pass

    def test_invalid_rendered_solidity_fails_compiler_gate(self):
        completed = subprocess.CompletedProcess([], 1, "", "Solidity syntax error")
        with (
            patch.object(demo.shutil, "which", return_value="/usr/bin/forge"),
            patch.object(demo.subprocess, "run", return_value=completed) as run,
        ):
            with self.assertRaisesRegex(RuntimeError, "forge build failed"):
                demo.validate_rendered_contract(DEMO_PATH)
            run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
