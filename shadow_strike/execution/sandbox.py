"""
shadow_strike.execution.sandbox
==================================
Two layers of isolation, matching architecture §2.6:

1. SandboxedSubprocess — process-level resource limits (CPU time, memory,
   max file size, no core dumps) applied via Python's stdlib `resource`
   module in the child's `preexec_fn`. This works on any POSIX system,
   RIGHT NOW, with zero extra dependencies — and is demonstrated below
   actually killing a runaway process.

2. The bundled Dockerfile (docker/sandbox.Dockerfile) — full container
   isolation (no outbound network except one allow-listed RPC host,
   read-only filesystem except /tmp scratch, non-root user, dropped
   capabilities). Layer 1 alone is NOT sufficient for untrusted
   Solidity/LLM-influenced code in production — it bounds resource
   *consumption*, not filesystem or network access. Both layers are
   meant to be used together; see ForgeRunner's docstring.
"""

from __future__ import annotations

import resource
import subprocess
import time
from dataclasses import dataclass


class SandboxLimitExceeded(RuntimeError):
    pass


@dataclass
class SandboxLimits:
    cpu_seconds: int = 20
    memory_bytes: int = 512 * 1024 * 1024    # 512 MB
    max_file_size_bytes: int = 50 * 1024 * 1024  # 50 MB — generated .t.sol / build artifacts
    wall_clock_seconds: int = 30              # backstop in case a process ignores SIGXCPU


def _apply_rlimits(limits: SandboxLimits):
    """Runs INSIDE the child process (via preexec_fn) before exec().
    Once these are set, the OS enforces them — the child cannot raise
    its own ceiling back up (RLIM_INFINITY is only settable with
    privileges this process should not have)."""
    resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
    resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
    resource.setrlimit(resource.RLIMIT_FSIZE, (limits.max_file_size_bytes, limits.max_file_size_bytes))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # no core dumps — may contain sensitive scenario data


class SandboxedSubprocess:
    """Drop-in wrapper: anywhere you'd call subprocess.run(cmd, ...) for
    an untrusted-code step (forge test, forge build, a future solc
    invocation), call SandboxedSubprocess(limits).run(cmd, ...) instead."""

    def __init__(self, limits: SandboxLimits | None = None):
        self.limits = limits or SandboxLimits()

    def run(self, cmd: list[str], **kw) -> subprocess.CompletedProcess:
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                preexec_fn=lambda: _apply_rlimits(self.limits),
                timeout=self.limits.wall_clock_seconds,
                capture_output=True,
                text=True,
                check=False,
                **kw,
            )
        except subprocess.TimeoutExpired as e:
            raise SandboxLimitExceeded(
                f"wall-clock limit ({self.limits.wall_clock_seconds}s) exceeded — "
                f"process did not respect its CPU rlimit in time"
            ) from e

        elapsed = time.monotonic() - start
        # RLIMIT_CPU delivers SIGXCPU (signal 24); a killed process shows
        # up as a negative returncode equal to -signal on POSIX.
        if proc.returncode == -24:
            raise SandboxLimitExceeded(
                f"CPU limit ({self.limits.cpu_seconds}s) exceeded after {elapsed:.1f}s wall time"
            )
        if proc.returncode == -9:
            raise SandboxLimitExceeded(f"process was killed (likely OOM against {self.limits.memory_bytes} byte limit)")
        return proc


if __name__ == "__main__":
    # Live proof: a deliberately runaway CPU-bound process gets killed by
    # the rlimit, not by us polling — this is a real OS-enforced boundary.
    tight_limits = SandboxLimits(cpu_seconds=1, memory_bytes=256 * 1024 * 1024, wall_clock_seconds=5)
    sandbox = SandboxedSubprocess(tight_limits)

    runaway = ["python3", "-c", "x = 0\nwhile True:\n    x += 1"]
    print(f"launching a CPU-unbounded loop under a {tight_limits.cpu_seconds}s CPU rlimit...")
    try:
        sandbox.run(runaway)
        print("UNEXPECTED: process completed without hitting the limit")
    except SandboxLimitExceeded as e:
        print(f"sandbox correctly killed it: {e}")

    print("\nrunning a well-behaved process under the same sandbox for comparison...")
    result = sandbox.run(["python3", "-c", "print('hello from inside the sandbox')"])
    print(f"well-behaved process: returncode={result.returncode} stdout={result.stdout.strip()!r}")
