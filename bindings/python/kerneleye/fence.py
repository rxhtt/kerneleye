"""
KernelEye Python SDK
Host-native Linux eBPF LSM Confinement Middleware for Autonomous AI Agents.
"""

import os
import signal
import subprocess
import time
import shutil
import functools
from typing import List, Optional, Union, Dict, Any, Callable


class KernelFence:
    """
    Context manager that attaches eBPF LSM confinement to a target worker PID
    or executes commands within an isolated, self-terminating process group.
    """

    def __init__(
        self,
        pid: Optional[int] = None,
        block_binaries: Optional[List[str]] = None,
        block_files: Optional[List[str]] = None,
        audit_only: bool = False,
        cryo_freeze: bool = False,
        phantom_sink: bool = False,
        honeypot_canary: bool = False,
        canary_tokens: bool = False,
        kill_on_violation: bool = True,
        scrub_env: bool = False,
        allow_env: Optional[List[str]] = None,
        audit_log: Optional[str] = None,
        workspace: Optional[str] = None,
        proxy_allow_registries: bool = False,
        proxy_port: int = 18080,
        allow_domains: Optional[List[str]] = None,
        allow_ips: Optional[List[str]] = None,
        daemon_path: Optional[str] = None,
    ):
        self.target_pid = pid
        self.block_binaries = block_binaries or ["curl", "wget", "nc", "ncat", "socat"]
        self.block_files = block_files or [
            "id_rsa",
            "id_ed25519",
            "credentials",
            ".env",
            "shadow",
            "authorized_keys",
        ]
        self.audit_only = audit_only
        self.cryo_freeze = cryo_freeze
        self.phantom_sink = phantom_sink
        self.honeypot_canary = honeypot_canary or canary_tokens
        self.canary_tokens = self.honeypot_canary
        self.kill_on_violation = kill_on_violation
        self.scrub_env = scrub_env
        self.allow_env = allow_env
        self.audit_log = audit_log
        self.workspace = workspace
        self.proxy_allow_registries = proxy_allow_registries
        self.proxy_port = proxy_port
        self.allow_domains = allow_domains
        self.allow_ips = allow_ips
        self._spawned_pgids: List[int] = []
        self._canary_paths: List[str] = []

        # Resolve daemon binary path
        if daemon_path:
            self.daemon_path = daemon_path
        else:
            found = shutil.which("kerneleye") or shutil.which("exec-snoop")
            if not found:
                for candidate in [
                    "./target/release/kerneleye",
                    "../target/release/kerneleye",
                    "../../target/release/kerneleye",
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
        if self.honeypot_canary:
            canary_path = os.path.join(self.workspace or os.getcwd(), ".env.canary")
            try:
                with open(canary_path, "w") as f:
                    f.write("# KernelEye Honeypot Canary Credential (Mirage VFS)\n")
                    f.write("AWS_SECRET_ACCESS_KEY=AKIA_CANARY_TRUMAN_SHOW_99812_PROD_FAKE\n")
                    f.write("OPENAI_API_KEY=sk-proj-canary-fake-token-never-leave-host-001\n")
                    f.write("EXFIL_SINK_URL=http://127.0.0.1:65530/canary_exfil\n")
                self._canary_paths.append(canary_path)
            except Exception:
                pass

        if self.target_pid is not None:
            self._start_daemon(self.target_pid)
        return self

    def _start_daemon(self, pid: int):
        cmd = [
            "sudo",
            self.daemon_path,
            "--fence-pid",
            str(pid),
            "--block",
            ",".join(self.block_binaries),
            "--block-files",
            ",".join(self.block_files),
        ]
        if self.audit_only:
            cmd.append("--audit-only")
        elif self.cryo_freeze:
            cmd.append("--cryo-freeze")
        elif self.kill_on_violation:
            cmd.append("--kill-on-violation")

        if self.phantom_sink:
            cmd.append("--phantom-sink")
        if self.scrub_env:
            cmd.append("--scrub-env")
        if self.allow_env:
            cmd.extend(["--allow-env", ",".join(self.allow_env)])
        if self.audit_log:
            cmd.extend(["--audit-log", self.audit_log])
        if self.workspace:
            cmd.extend(["--workspace", self.workspace])
        if self.proxy_allow_registries:
            cmd.append("--proxy-allow-registries")
            cmd.extend(["--proxy-port", str(self.proxy_port)])
        if self.allow_domains:
            cmd.extend(["--allow-domain", ",".join(self.allow_domains)])
        if self.allow_ips:
            cmd.extend(["--allow-ip", ",".join(self.allow_ips)])
        if self.canary_tokens:
            cmd.append("--canary-tokens")

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=os.setpgrp,
        )
        time.sleep(0.35)

    def run_direct(
        self,
        command: List[str],
        timeout: Optional[float] = None,
    ) -> subprocess.CompletedProcess:
        """
        Executes command directly using `kerneleye run -- <CMD>` (zero-race in-kernel confinement).
        """
        cmd = ["sudo", self.daemon_path]
        if self.block_binaries:
            cmd.extend(["--block", ",".join(self.block_binaries)])
        if self.block_files:
            cmd.extend(["--block-files", ",".join(self.block_files)])
        if self.audit_only:
            cmd.append("--audit-only")
        elif self.cryo_freeze:
            cmd.append("--cryo-freeze")
        elif self.kill_on_violation:
            cmd.append("--kill-on-violation")
        if self.phantom_sink:
            cmd.append("--phantom-sink")
        if self.scrub_env:
            cmd.append("--scrub-env")
        if self.allow_env:
            cmd.extend(["--allow-env", ",".join(self.allow_env)])
        if self.audit_log:
            cmd.extend(["--audit-log", self.audit_log])
        if self.workspace:
            cmd.extend(["--workspace", self.workspace])
        if self.proxy_allow_registries:
            cmd.append("--proxy-allow-registries")
            cmd.extend(["--proxy-port", str(self.proxy_port)])
        if self.allow_domains:
            cmd.extend(["--allow-domain", ",".join(self.allow_domains)])
        if self.allow_ips:
            cmd.extend(["--allow-ip", ",".join(self.allow_ips)])
        if self.canary_tokens:
            cmd.append("--canary-tokens")

        cmd.append("run")
        cmd.append("--")
        cmd.extend(command)

        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )

    def run_command(
        self,
        command: Union[str, List[str]],
        timeout: Optional[float] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> subprocess.CompletedProcess:
        """
        Executes a command inside an isolated process group fenced by eBPF LSM.
        Guarantees that on exit, any lingering background forks are wiped with SIGKILL.
        """
        eff_cwd = cwd or self.workspace
        if isinstance(command, str):
            shell_cmd = f"echo $$ > /tmp/_kf_pid_{os.getpid()}; exec {command}"
            worker_proc = subprocess.Popen(
                ["bash", "-c", shell_cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=eff_cwd,
                env=env,
                preexec_fn=os.setpgrp,
            )
        else:
            worker_proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=eff_cwd,
                env=env,
                preexec_fn=os.setpgrp,
            )

        pgid = os.getpgid(worker_proc.pid)
        self._spawned_pgids.append(pgid)

        # Attach fence if not already attached to this worker
        if self._proc is None and self.target_pid is None:
            self._start_daemon(worker_proc.pid)

        try:
            stdout, stderr = worker_proc.communicate(timeout=timeout)
            return subprocess.CompletedProcess(
                args=command,
                returncode=worker_proc.returncode,
                stdout=stdout,
                stderr=stderr,
            )
        finally:
            # Immediate cleanup: prevent delayed-fork attacks
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        # 1. Kill any lingering process groups spawned in the block
        for pgid in self._spawned_pgids:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self._spawned_pgids.clear()

        # 2. Clean up canary honeypot files
        for path in self._canary_paths:
            try:
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass
        self._canary_paths.clear()

        # 3. Stop daemon
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=1.0)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None


def fence_agent(
    block_binaries: Optional[List[str]] = None,
    protect_files: Optional[List[str]] = None,
    audit_only: bool = False,
    cryo_freeze: bool = False,
    phantom_sink: bool = False,
    honeypot_canary: bool = False,
    canary_tokens: bool = False,
    kill_on_violation: bool = True,
    scrub_env: bool = False,
    allow_env: Optional[List[str]] = None,
    audit_log: Optional[str] = None,
    workspace: Optional[str] = None,
    proxy_allow_registries: bool = False,
    daemon_path: Optional[str] = None,
) -> Callable:
    """
    Decorator that attaches in-kernel eBPF LSM confinement to the current process
    and all descendant child processes during the execution of the decorated function.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            fence = KernelFence(
                pid=os.getpid(),
                block_binaries=block_binaries,
                block_files=protect_files,
                audit_only=audit_only,
                cryo_freeze=cryo_freeze,
                phantom_sink=phantom_sink,
                honeypot_canary=honeypot_canary or canary_tokens,
                kill_on_violation=kill_on_violation,
                scrub_env=scrub_env,
                allow_env=allow_env,
                audit_log=audit_log,
                workspace=workspace,
                proxy_allow_registries=proxy_allow_registries,
                daemon_path=daemon_path,
            )
            with fence:
                return func(*args, **kwargs)
        return wrapper
    return decorator
