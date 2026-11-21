"""Regression checks for the declared local and CI quality gates."""

import ast
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]


class TestCIConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project = (ROOT / "pyproject.toml").read_text()
        cls.workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        # These TOML settings are arrays of quoted strings, also valid Python
        # literals. Keep this check usable on Python 3.10 without tomllib.
        dev = re.search(r"(?ms)^dev = (\[.*?^\])", cls.project)
        cls.dev = ast.literal_eval(dev.group(1))

    def test_lint_scope_rules_and_version_match(self):
        command = "ruff check shadow_strike/ tests/ examples/"
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn("lint:\n\t" + command + "\n", makefile)
        steps = self.workflow["jobs"]["lint"]["steps"]
        self.assertIn(command, [step.get("run") for step in steps])
        self.assertIn("pip install ruff==0.17.6", [step.get("run") for step in steps])
        self.assertIn("ruff==0.17.6", self.dev)
        # The rule set lives in [tool.ruff.lint]: a top-level `select` under
        # [tool.ruff] is deprecated in ruff 0.17 and prints a warning on
        # every run.
        ruff_top = self.project.split("[tool.ruff]\n", 1)[1].split("\n[", 1)[0]
        self.assertNotRegex(ruff_top, r"(?m)^select = ")
        ruff = self.project.split("[tool.ruff.lint]\n", 1)[1].split("\n[", 1)[0]
        select = re.search(r"(?m)^select = (\[.*\])$", ruff)
        self.assertIsNotNone(select)
        self.assertEqual(ast.literal_eval(select.group(1)), ["E4", "E7", "E9", "F"])

    def test_dev_extra_includes_optional_regression_dependencies(self):
        self.assertIn("httpx>=0.27", self.dev)
        self.assertIn("sqlalchemy>=2.0", self.dev)

    def test_compiler_prerequisite_gate_fails_on_missing_tools(self):
        steps = self.workflow["jobs"]["test"]["steps"]
        names = [step.get("name") for step in steps]
        gate = names.index("Verify Solidity compiler prerequisites")
        self.assertLess(names.index("Install forge-std"), gate)
        self.assertLess(gate, names.index("Run test suite"))
        script = steps[gate]["run"]
        for missing in (None, "forge", "solc", "forge-std", "wrong-solc"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                binary = root / "bin"
                binary.mkdir()
                solc = root / ".svm/0.8.19/solc-0.8.19"
                solc.parent.mkdir(parents=True)
                if missing != "forge":
                    forge = binary / "forge"
                    forge.write_text('#!/bin/sh\nprintf "%s\\n" "$*"\n')
                    forge.chmod(0o755)
                if missing != "solc":
                    version = "0.8.20" if missing == "wrong-solc" else "0.8.19"
                    solc.write_text(f"#!/bin/sh\necho 'Version: {version}+commit.test'\n")
                    solc.chmod(0o755)
                if missing != "forge-std":
                    (root / "lib/forge-std").mkdir(parents=True)
                environment = dict(os.environ, HOME=str(root), PATH=str(binary))
                environment.pop("FOUNDRY_SOLC", None)
                # Supply only the external utility needed by the gate so the
                # host's installed Forge cannot mask the missing-tool case.
                (binary / "grep").symlink_to("/usr/bin/grep")
                result = subprocess.run(
                    ["/bin/bash", "-e", "-o", "pipefail", "-c", script],
                    cwd=root, env=environment, capture_output=True, text=True,
                )
                if missing is None:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("--version", result.stdout)
                    self.assertIn("build --use 0.8.19", result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
