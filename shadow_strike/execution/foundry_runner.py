"""
shadow_strike.execution.foundry_runner
=========================================
Production executor: shells out to `forge test` against a generated
.t.sol file, inside a resource-bounded subprocess, and parses the JSON
output into an ExecutionResult.

Requires Foundry (https://getfoundry.sh) installed and a real RPC URL
in the scenario's initial_state.fork_url. Not runnable inside a
network-isolated sandbox — see mock_executor.py for an offline
stand-in used for development/demo/CI without external calls.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from shadow_strike.core.models import AttackScenario, ExecutionResult
from shadow_strike.execution.sandbox import SandboxedSubprocess, SandboxLimits, SandboxLimitExceeded

# Hard ceiling — a single scenario attempt must never hang the pipeline.
DEFAULT_TIMEOUT_SECONDS = 90


class FoundryNotInstalledError(RuntimeError):
    pass


class ForgeRunner:
    def __init__(self, foundry_project_root: Path, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
                 sandbox_limits: SandboxLimits | None = None):
        self.root = Path(foundry_project_root)
        self.timeout_seconds = timeout_seconds
        # process-level resource bound — see sandbox.py. This is layer 1
        # of 2; layer 2 (container/network isolation) must be provided by
        # whatever invokes ForgeRunner (see docker/sandbox.Dockerfile).
        # Both matter: this layer stops a runaway/OOM process; it does
        # NOT stop a malicious process from reading the filesystem or
        # reaching the network, which only the container boundary does.
        self.sandbox = SandboxedSubprocess(sandbox_limits or SandboxLimits(
            cpu_seconds=timeout_seconds, wall_clock_seconds=timeout_seconds + 10,
        ))
        if shutil.which("forge") is None:
            raise FoundryNotInstalledError(
                "`forge` not found on PATH. Install Foundry (https://getfoundry.sh) "
                "to use ForgeRunner, or use shadow_strike.execution.mock_executor "
                "for offline development."
            )

    def run(self, scenario: AttackScenario, test_file: Path) -> ExecutionResult:
        """Run exactly one generated test file and return a structured result.

        Isolation notes (see architecture §2.6 — enforce these at the
        deployment layer, this class assumes they're already in place):
          - invoke this *inside* a container with no outbound network
            except the single allow-listed RPC host
          - set CPU/memory ulimits on the container, not just the
            Python-level timeout below
          - mount the foundry project read-only except for a scratch
            /tmp the container throws away after the run
        """
        contract_name = f"ShadowStrike_{scenario.scenario_id}"
        cmd = [
            "forge", "test",
            "--match-contract", contract_name,
            "--fork-url", scenario.initial_state.fork_url,
            "--fork-block-number", str(scenario.initial_state.fork_block),
            "-vvvv",
            "--json",
        ]
        try:
            proc = self.sandbox.run(cmd, cwd=self.root)
        except SandboxLimitExceeded as e:
            return ExecutionResult(
                scenario_id=scenario.scenario_id,
                reverted=True,
                revert_reason=f"sandbox limit exceeded: {e}",
                state_vars={},
                state_diff={},
                call_trace=[],
                gas_used=0,
                engine="foundry",
            )

        return self._parse_result(scenario, proc)

    # ------------------------------------------------------------------
    def _parse_result(self, scenario: AttackScenario, proc: subprocess.CompletedProcess) -> ExecutionResult:
        state_vars: dict = {}
        logs: list[str] = []
        reverted = proc.returncode != 0
        revert_reason = None

        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            payload = None

        if payload:
            # forge --json shape varies by version; this extracts the
            # emit log_named_uint(...) lines, which is the stable contract
            # between compiler.py's emitted lines and this parser.
            for test_result in _walk_test_results(payload):
                for line in test_result.get("decoded_logs", []) or []:
                    logs.append(line)
                    m = re.match(r"^(\w+):\s*([0-9]+)$", line.strip())
                    if m:
                        key, value = m.group(1), int(m.group(2))
                        state_vars[key] = value
                if test_result.get("success") is False:
                    revert_reason = test_result.get("reason") or "assertion failed"

        state_vars = _nest_eth_vars(state_vars)
        state_diff = _extract_state_diff(logs)

        return ExecutionResult(
            scenario_id=scenario.scenario_id,
            reverted=reverted,
            revert_reason=revert_reason,
            state_vars=state_vars,
            state_diff=state_diff,
            call_trace=[{"raw_stderr_tail": proc.stderr[-2000:]}] if proc.stderr else [],
            gas_used=state_vars.get("gas_used", 0) if isinstance(state_vars.get("gas_used"), int) else 0,
            raw_logs=logs,
            engine="foundry",
        )


def _walk_test_results(payload: dict):
    # forge's --json top level is {file_path: {"test_results": {test_name: {...}}}}
    for file_result in payload.values():
        if isinstance(file_result, dict) and "test_results" in file_result:
            yield from file_result["test_results"].values()


def _extract_state_diff(logs: list[str]) -> dict:
    """Parses the `<alias>_slots_written` / `<alias>_written_slot`
    emits produced by compiler.py's record_state_diff=True block (real
    forge-std vm.record()/vm.accesses() cheatcodes — not simulated) into
    {alias: {"slots_written": N, "written_slots": [hex, ...]}}."""
    diff: dict[str, dict] = {}
    current_alias = None
    for line in logs:
        m = re.match(r"^(\w+)_slots_written:\s*(\d+)$", line.strip())
        if m:
            current_alias = m.group(1)
            diff.setdefault(current_alias, {"slots_written": int(m.group(2)), "written_slots": []})
            continue
        m2 = re.match(r"^(\w+)_written_slot:\s*(0x[0-9a-fA-F]+)$", line.strip())
        if m2:
            alias = m2.group(1)
            diff.setdefault(alias, {"slots_written": 0, "written_slots": []})
            diff[alias]["written_slots"].append(m2.group(2))
    return diff


def _nest_eth_vars(flat: dict[str, int]) -> dict:
    """Turn {'attacker_eth_before': 1, 'attacker_eth_after': 11, 'vault_eth_before': ...}
    into {'attacker': {'eth_balance_before': 1, 'eth_balance_after': 11}, 'vault': {...}}
    so it matches the dotted-name convention success_conditions expect."""
    nested: dict[str, dict] = {}
    for key, value in flat.items():
        m = re.match(r"^(\w+)_eth_(before|after)$", key)
        if m:
            alias, when = m.group(1), m.group(2)
            nested.setdefault(alias, {})[f"eth_balance_{when}"] = value
        else:
            nested[key] = value
    return nested
