# exec-snoop-rs

`exec-snoop-rs` is a low-overhead Linux process execution monitor written in pure Rust using the Aya eBPF framework. It hooks into the kernel `sched:sched_process_exec` tracepoint to capture binary execution events, extracts process ancestry directly from `task_struct`, and streams zero-copy telemetry to an async userspace daemon via an eBPF ring buffer.

The project does not depend on LLVM/Clang runtime compilers, BCC Python wrappers, or kernel headers at runtime. The probe compiles to an independent eBPF ELF binary that executes safely within the kernel verifier constraints.

## System Architecture

The pipeline consists of three core components communicating across the kernel-userspace boundary:

```text
[ Linux Kernel: sched:sched_process_exec ]
│
▼
[ eBPF Probe: aya-ebpf (#![no_std]) ]
├── Task PID/TID extraction (bpf_get_current_pid_tgid)
├── In-kernel PPID resolution (task_struct->real_parent->tgid)
├── Command invocation reading (bpf_probe_read_user_str)
└── Zero-copy push to BPF_MAP_TYPE_RINGBUF (256 KB)
│
(Shared Memory Ring Buffer)
│
▼
[ Userspace Daemon: tokio + aya AsyncFd ]
├── Event-driven polling via epoll/AsyncFd
├── C-ABI deserialization (aya::Pod)
└── Drop monitoring via BPF_MAP_TYPE_PERCPU_ARRAY
```

### ABI Memory Alignment

Cross-boundary data integrity is maintained using a strict C-compatible memory layout in `exec-snoop-common`:

| Field | Type | Offset | Description |
|---|---|---|---|
| `pid` | `u32` | 0 | Thread Group ID / Process ID |
| `ppid` | `u32` | 4 | Parent Process ID resolved in-kernel |
| `args_len` | `usize` | 8 | Length of captured argument string |
| `comm` | `[u8; 16]` | 16 | Executable name (`TASK_COMM_LEN`) |
| `args` | `[u8; 256]` | 32 | Dynamic invocation string / path |

Total memory footprint per event is strictly fixed and padded to prevent misaligned reads on 64-bit systems.

## Engineering Highlights

- In-Kernel Lineage Resolution: Unlike userspace monitors that query `/proc/[pid]/stat` after an event triggers, `exec-snoop-rs` reads the parent pointer from `task_struct->real_parent` directly inside the probe. This prevents lineage resolution failures caused by short-lived processes terminating before `/proc` can be read.
- Observability Under Load: Standard eBPF monitors fail silently when ring buffers saturate. This implementation maintains a lockless `PerCpuArray` drop counter map. When `ringbuf.reserve()` fails during high-throughput execution bursts, the probe increments a drop metric without cross-core lock contention.
- Zero Runtime C Dependencies: Built entirely on `aya` and `aya-ebpf`, allowing self-contained binary distribution without runtime GCC/Clang tooling or C libraries.

## Prerequisites

- Linux kernel 5.8 or newer (tested on 7.0.0-31-generic with `CONFIG_BPF_SYSCALL=y`)
- Rust stable toolchain and nightly channel (for compiling to `bpfel-unknown-none`)
- `bpf-linker` (`cargo install bpf-linker`)
- Root access (`CAP_BPF` / `CAP_SYS_ADMIN` required to load eBPF programs into the kernel)

## Building from Source

To prevent memory exhaustion during parallel compilation, throttle build concurrency:

```bash
# Clone the repository
git clone https://github.com/rxhtt/exec-snoop-rs.git
cd exec-snoop-rs/exec-snoop

# Compile both the eBPF probe and the userspace daemon
cargo xtask build --release -j 2
```

The build produces two artifacts:

- Kernel probe: `target/bpfel-unknown-none/release/exec-snoop`
- Userspace loader: `target/release/exec-snoop`

## Usage

Start the daemon with administrative privileges:

```bash
sudo ./target/release/exec-snoop
```

Example terminal output:

```text
[+] eBPF program loaded and attached to sched:sched_process_exec
[+] Streaming process executions (Press Ctrl+C to stop)...
PID      PPID     COMM             ARGS
--------------------------------------------------------------------------------
312480   301120   git              git status
312485   301120   cargo            cargo xtask build --release -j 2
312512   312485   rustc            rustc --crate-name exec_snoop ...
```

## Stress Testing & Drop Detection

An automated stress testing harness is included to evaluate ring buffer saturation under burst conditions:

```bash
./stress_test.sh
```

The script spawns 500 concurrent child processes. The userspace daemon polls drop counters every five seconds and reports any telemetry loss to stdout.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
