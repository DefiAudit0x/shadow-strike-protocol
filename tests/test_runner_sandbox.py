"""Regressions for local Forge execution and subprocess resource boundaries."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from shadow_strike.execution.foundry_runner import ForgeRunner
from shadow_strike.execution.sandbox import SandboxedSubprocess, SandboxLimitExceeded, SandboxLimits


def scenario():
    return SimpleNamespace(scenario_id="probe", initial_state=SimpleNamespace(fork_url="", fork_block=0))


def test_local_command_omits_fork_flags(tmp_path):
    with patch("shutil.which", return_value="forge"):
        runner = ForgeRunner(tmp_path)
    with patch.object(runner.sandbox, "run", return_value=subprocess.CompletedProcess([], 0, "{}", "")) as run:
        runner.run(scenario(), tmp_path / "Probe.t.sol")
    command = run.call_args.args[0]
    assert "--fork-url" not in command
    assert "--fork-block-number" not in command


def test_forge_failure_status_and_reason(tmp_path):
    forge = tmp_path / "forge"
    payload = {"Probe.t.sol:Probe": {"test_results": {"test_probe()": {
        "status": "Failure", "reason": "assertion failed: expected 42", "decoded_logs": [],
    }}}}
    forge.write_text(f"#!{sys.executable}\nimport sys\nprint({json.dumps(payload)!r})\nsys.exit(1)\n")
    forge.chmod(0o755)
    with patch.dict(os.environ, {"PATH": str(tmp_path) + os.pathsep + os.environ["PATH"]}):
        result = ForgeRunner(tmp_path).run(scenario(), tmp_path / "Probe.t.sol")
    assert result.reverted
    assert result.revert_reason == "assertion failed: expected 42"


def test_sigkill_does_not_guess_oom_or_cpu():
    with pytest.raises(SandboxLimitExceeded, match="SIGKILL; cause unknown"):
        SandboxedSubprocess().run([sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGKILL)"])


def test_cpu_hard_limit_does_not_report_likely_oom():
    with pytest.raises(SandboxLimitExceeded) as failure:
        SandboxedSubprocess(SandboxLimits(cpu_seconds=1, wall_clock_seconds=5)).run([
            sys.executable, "-c", "while True: pass",
        ])
    assert "likely OOM" not in str(failure.value)
    assert "CPU" in str(failure.value)


def test_timeout_kills_grandchild(tmp_path):
    pid_file = tmp_path / "grandchild.pid"
    code = (
        "import subprocess, sys, time; from pathlib import Path; "
        "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
        f"Path({str(pid_file)!r}).write_text(str(p.pid)); time.sleep(60)"
    )
    with pytest.raises(SandboxLimitExceeded, match="wall-clock"):
        SandboxedSubprocess(SandboxLimits(wall_clock_seconds=1)).run([sys.executable, "-c", code])
    pid = int(pid_file.read_text())
    # An orphan can remain a zombie until the host's init reaps it; it cannot execute.
    for _ in range(100):
        stat = Path(f"/proc/{pid}/stat")
        if not stat.exists() or stat.read_text().split()[2] == "Z":
            break
        time.sleep(0.01)
    else:
        os.kill(pid, 9)
        pytest.fail("grandchild survived sandbox timeout")


def test_captured_streams_are_bounded():
    cap = 4096
    result = SandboxedSubprocess(SandboxLimits(max_output_bytes=cap)).run([
        sys.executable, "-c", "import os; os.write(1, b'x' * 1000000); os.write(2, b'y' * 1000000)",
    ])
    assert result.returncode == 0
    for output in (result.stdout, result.stderr):
        assert len(output.encode()) <= cap
        assert output.endswith("\n[output truncated]\n")
