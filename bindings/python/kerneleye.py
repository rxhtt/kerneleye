"""
KernelEye Python SDK
Host-native Linux eBPF LSM Confinement Middleware for Autonomous AI Agents.
"""

import os
import subprocess
import time
import shutil
from typing import List, Optional


class KernelFence:
    """
    Context manager that attaches eBPF LSM confinement to the current process
    or a target worker PID and all its descendant subshells.
    """

    def __init__(
        self,
        pid: Optional[int] = None,
        block_binaries: Optional[List[str]] = None,
        block_files: Optional[List[str]] = None,
        kill_on_violation: bool = True,
        daemon_path: Optional[str] = None,
    ):
        self.target_pid = pid or os.getpid()
        self.block_binaries = block_binaries or ["curl", "wget", "nc", "ncat", "socat"]
        self.block_files = block_files or [
            "id_rsa",
            "id_ed25519",
            "credentials",
            ".env",
            "shadow",
            "authorized_keys",
        ]
        self.kill_on_violation = kill_on_violation

        # Resolve daemon binary path
        if daemon_path:
            self.daemon_path = daemon_path
        else:
            found = shutil.which("kerneleye") or shutil.which("exec-snoop")
            if not found:
                # Fallback to local build paths
                for candidate in [
                    "./target/release/exec-snoop",
                    "../target/release/exec-snoop",
                    "/usr/local/bin/kerneleye",
                ]:
                    if os.path.exists(candidate):
                        found = candidate
                        break
            self.daemon_path = found or "exec-snoop"

        self._proc: Optional[subprocess.Popen] = None

    def __enter__(self):
        cmd = [
            "sudo",
            self.daemon_path,
            "--fence-pid",
            str(self.target_pid),
            "--block",
            ",".join(self.block_binaries),
            "--block-files",
            ",".join(self.block_files),
        ]
        if self.kill_on_violation:
            cmd.append("--kill-on-violation")

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=os.setpgrp,
        )

        # Give the eBPF loader 300ms to attach LSM hooks and populate BTF maps
        time.sleep(0.35)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=1.0)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
