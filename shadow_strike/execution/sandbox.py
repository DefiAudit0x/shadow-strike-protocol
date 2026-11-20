"""
shadow_strike.execution.sandbox
==================================
SandboxedSubprocess applies POSIX resource limits to host subprocesses.
These limits do not isolate filesystem or network access. The bundled
Docker container is manual-only and does not enforce an egress allowlist.
"""

from __future__ import annotations

import os
import resource
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass


class SandboxLimitExceeded(RuntimeError):
    pass


@dataclass
class SandboxLimits:
    cpu_seconds: int = 20
    # RLIMIT_AS: 1536 MiB verified with an offline forge test (Forge 1.9.0, solc 0.8.19).
    memory_bytes: int = 1536 * 1024 * 1024
    max_file_size_bytes: int = 50 * 1024 * 1024  # 50 MB — generated .t.sol / build artifacts
    wall_clock_seconds: int = 30              # backstop in case a process ignores SIGXCPU
    max_output_bytes: int = 1024 * 1024  # per stream, including truncation marker


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
        marker = b"\n[output truncated]\n"
        cap = self.limits.max_output_bytes
        if cap < len(marker):
            raise ValueError("max_output_bytes must fit the truncation marker")
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        truncated = set()
        with subprocess.Popen(
            cmd,
            preexec_fn=lambda: _apply_rlimits(self.limits),  # noqa: PLW1509 -- set limits before exec
            start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw,
        ) as child:
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ, "stdout")
                    selector.register(child.stderr, selectors.EVENT_READ, "stderr")
                    while selector.get_map() or child.poll() is None:
                        remaining = self.limits.wall_clock_seconds - (time.monotonic() - start)
                        if remaining <= 0:
                            raise SandboxLimitExceeded(
                                f"wall-clock limit ({self.limits.wall_clock_seconds}s) exceeded"
                            )
                        for key, _ in selector.select(min(remaining, 0.1)):
                            chunk = os.read(key.fileobj.fileno(), 65536)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                continue
                            name = key.data
                            buffer = buffers[name]
                            available = cap - len(buffer)
                            buffer.extend(chunk[:available])
                            if len(chunk) > available:
                                truncated.add(name)
                    child.wait()
            finally:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
            for name in truncated:
                buffers[name][-len(marker):] = marker
            proc = subprocess.CompletedProcess(
                cmd, child.returncode,
                buffers["stdout"].decode(errors="replace"), buffers["stderr"].decode(errors="replace"),
            )

        elapsed = time.monotonic() - start
        # RLIMIT_CPU delivers SIGXCPU (signal 24); a killed process shows
        # up as a negative returncode equal to -signal on POSIX.
        if proc.returncode == -signal.SIGXCPU:
            raise SandboxLimitExceeded(
                f"CPU limit ({self.limits.cpu_seconds}s) exceeded after {elapsed:.1f}s wall time"
            )
        if proc.returncode == -signal.SIGKILL:
            raise SandboxLimitExceeded("process was killed by SIGKILL; cause unknown (CPU, OOM, or external kill)")
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
