use aya::Btf;
use aya::maps::{Array, HashMap, PerCpuArray, RingBuf};
use aya::programs::{Lsm, TracePoint};
use clap::Parser;
use exec_snoop_common::{ConfinementViolationEvent, MAX_ARGS_LEN, ProcessExecEvent};
use std::convert::TryInto;
use std::time::Duration;
use tokio::signal;

#[derive(Debug, Parser)]
#[command(
    name = "kerneleye",
    about = "Zero-container Linux eBPF LSM process isolation and network egress denial for autonomous AI agents",
    version = "0.2.0"
)]
struct Opt {
    /// Target PID(s) to fence. Any child spawned by these PIDs will be restricted.
    #[arg(long = "fence-pid", value_name = "PID")]
    fence_pid: Vec<u32>,

    /// Terminate the fenced root agent session immediately upon confinement violation.
    #[arg(long = "kill-on-violation")]
    kill_on_violation: bool,

    /// Comma-separated list of unauthorized binary basenames to block for fenced agents.
    #[arg(long = "block", default_value = "curl,wget,nc,ncat,socat")]
    block: String,

    /// Comma-separated list of sensitive file basenames to block for fenced agents.
    #[arg(
        long = "block-files",
        default_value = "id_rsa,id_ed25519,credentials,.env,shadow,authorized_keys"
    )]
    block_files: String,

    /// Run in audit-only mode: log confinement violations to telemetry without blocking operations.
    #[arg(long = "audit-only")]
    audit_only: bool,

    /// Freeze the offending process tree in RAM (SIGSTOP) instead of terminating it, preserving state for inspection.
    #[arg(long = "cryo-freeze")]
    cryo_freeze: bool,

    /// Launch active counter-deception Phantom Sinkhole on 127.0.0.1:65530 (captures exfiltration & returns HTTP 200).
    #[arg(long = "phantom-sink")]
    phantom_sink: bool,
}

fn format_time() -> String {
    let now = std::time::SystemTime::now();
    let duration = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs() as libc::time_t;
    let mut tm = libc::tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: std::ptr::null(),
    };
    unsafe {
        libc::localtime_r(&secs, &mut tm);
        let mut buf = [0u8; 32];
        let len = libc::strftime(
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            b"%H:%M:%S\0".as_ptr() as *const libc::c_char,
            &tm,
        );
        if len > 0 {
            String::from_utf8_lossy(&buf[..len]).into_owned()
        } else {
            format!("{secs}")
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _opt = Opt::parse();

    // Bump RLIMIT_MEMLOCK so kernel allows allocating eBPF maps
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

    #[cfg(debug_assertions)]
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/exec-snoop"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/exec-snoop"
    ))?;

    let program: &mut TracePoint = bpf
        .program_mut("exec_snoop")
        .ok_or("program 'exec_snoop' not found")?
        .try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    println!("[+] eBPF program loaded and attached to sched:sched_process_exec");

    if let Some(fork_prog) = bpf.program_mut("process_fork") {
        let fork_program: Result<&mut TracePoint, _> = fork_prog.try_into();
        match fork_program {
            Ok(p) => {
                if let Err(e) = p.load() {
                    eprintln!("[!] Failed to load process_fork: {e}");
                } else if let Err(e) = p.attach("sched", "sched_process_fork") {
                    eprintln!("[!] Failed to attach sched:sched_process_fork: {e}");
                } else {
                    println!("[+] eBPF fork tracker attached to sched:sched_process_fork");
                }
            }
            Err(e) => eprintln!("[!] Failed to convert process_fork to TracePoint: {e}"),
        }
    }

    let btf = match Btf::from_sys_fs() {
        Ok(b) => Some(b),
        Err(e) => {
            eprintln!("[!] Failed to read BTF from sysfs: {e}");
            None
        }
    };

    if let Some(ref btf) = btf {
        let lsm_hooks = [
            ("bprm_check_security", "blocking configured binaries"),
            ("socket_connect", "blocking AF_INET/AF_INET6 egress"),
            (
                "socket_sendmsg",
                "blocking connectionless UDP / datagram egress",
            ),
            ("file_open", "blocking sensitive credential file access"),
            (
                "task_kill",
                "anti-tamper: preventing rogue processes from signaling daemon",
            ),
            (
                "ptrace_access_check",
                "anti-tamper: preventing ptrace of unfenced processes",
            ),
            (
                "inode_link",
                "anti-evasion: blocking hard links to sensitive files",
            ),
            (
                "inode_rename",
                "anti-evasion: blocking renames of sensitive files",
            ),
            (
                "inode_unlink",
                "workspace guard: blocking deletion of critical files",
            ),
        ];

        for (hook_name, desc) in lsm_hooks {
            if let Some(prog) = bpf.program_mut(hook_name) {
                let lsm_program: Result<&mut Lsm, _> = prog.try_into();
                match lsm_program {
                    Ok(lsm_prog) => match lsm_prog.load(hook_name, btf) {
                        Ok(()) => match lsm_prog.attach() {
                            Ok(_) => println!("[+] eBPF LSM hook attached: {hook_name} ({desc})"),
                            Err(e) => eprintln!("[!] Failed to attach LSM hook {hook_name}: {e}"),
                        },
                        Err(e) => eprintln!("[!] Failed to load LSM program {hook_name}: {e}"),
                    },
                    Err(e) => eprintln!("[!] Failed to convert {hook_name} to Lsm: {e}"),
                }
            }
        }
    }

    if let Some(map) = bpf.map_mut("AUDIT_MODE") {
        if let Ok(mut audit_map) = Array::<_, u8>::try_from(map) {
            let val: u8 = if _opt.audit_only { 1 } else { 0 };
            let _ = audit_map.set(0, val, 0);
            if _opt.audit_only {
                println!("[*] AUDIT MODE ACTIVE: Violations will be logged without blocking.");
            }
        }
    }

    if let Some(map) = bpf.map_mut("DAEMON_PID") {
        if let Ok(mut daemon_map) = Array::<_, u32>::try_from(map) {
            let my_pid = std::process::id();
            let _ = daemon_map.set(0, my_pid, 0);
            println!("[+] Anti-tamper active: Protected daemon PID {my_pid} against signals");
        }
    }

    if let Some(map) = bpf.map_mut("BLOCKED_BINARIES") {
        if let Ok(mut blocked_map) = HashMap::<_, [u8; 16], u8>::try_from(map) {
            for raw_name in _opt.block.split(',') {
                let name = raw_name.trim();
                if name.is_empty() {
                    continue;
                }
                let mut key = [0u8; 16];
                let bytes = name.as_bytes();
                let len = bytes.len().min(15);
                key[..len].copy_from_slice(&bytes[..len]);
                if let Err(e) = blocked_map.insert(key, 1, 0) {
                    eprintln!("[!] Failed to insert '{name}' into BLOCKED_BINARIES map: {e}");
                }
            }
            println!("[+] Populated BLOCKED_BINARIES policy: {}", _opt.block);
        }
    }

    if let Some(map) = bpf.map_mut("BLOCKED_FILES") {
        if let Ok(mut blocked_map) = HashMap::<_, [u8; 16], u8>::try_from(map) {
            for raw_name in _opt.block_files.split(',') {
                let name = raw_name.trim();
                if name.is_empty() {
                    continue;
                }
                let mut key = [0u8; 16];
                let bytes = name.as_bytes();
                let len = bytes.len().min(15);
                key[..len].copy_from_slice(&bytes[..len]);
                if let Err(e) = blocked_map.insert(key, 1, 0) {
                    eprintln!("[!] Failed to insert '{name}' into BLOCKED_FILES map: {e}");
                }
            }
            println!("[+] Populated BLOCKED_FILES policy: {}", _opt.block_files);
        }
    }

    let mut protected_agent_pids: HashMap<_, u32, u32> = HashMap::try_from(
        bpf.map_mut("PROTECTED_AGENT_PIDS")
            .ok_or("PROTECTED_AGENT_PIDS map not found")?,
    )?;

    if _opt.fence_pid.is_empty() {
        println!("[i] No --fence-pid specified. Running telemetry without agent restrictions.");
    } else {
        for &pid in &_opt.fence_pid {
            protected_agent_pids.insert(pid, 1, 0)?;
            println!("[+] Kernel map populated: PID {pid} fenced.");
        }
    }

    println!("[+] Streaming process executions (Press Ctrl+C to stop)...");

    let ring_buf = RingBuf::try_from(bpf.take_map("RINGBUF").ok_or("RINGBUF map not found")?)?;
    let mut async_ring_buf = unsafe { tokio::io::unix::AsyncFd::register(ring_buf) }?;

    let violations_buf = bpf
        .take_map("VIOLATIONS")
        .and_then(|m| RingBuf::try_from(m).ok());
    let mut async_violations = match violations_buf {
        Some(rb) => unsafe { tokio::io::unix::AsyncFd::register(rb).ok() },
        None => None,
    };

    let dropped_events: PerCpuArray<_, u64> = PerCpuArray::try_from(
        bpf.take_map("DROPPED_EVENTS")
            .ok_or("DROPPED_EVENTS map not found")?,
    )?;

    let mut drop_interval = tokio::time::interval(Duration::from_secs(5));
    // Consume initial tick so interval fires 5s from now
    drop_interval.tick().await;

    if _opt.phantom_sink {
        tokio::spawn(async move {
            let listener = match tokio::net::TcpListener::bind("127.0.0.1:65530").await {
                Ok(l) => {
                    println!(
                        "[+] Mirage Egress: Phantom Sinkhole active on 127.0.0.1:65530 (Counter-Deception)"
                    );
                    l
                }
                Err(e) => {
                    eprintln!("[!] Failed to bind Phantom Sinkhole to 127.0.0.1:65530: {e}");
                    return;
                }
            };

            loop {
                if let Ok((mut socket, addr)) = listener.accept().await {
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = [0u8; 4096];
                        if let Ok(n) = socket.read(&mut buf).await {
                            if n > 0 {
                                let payload = String::from_utf8_lossy(&buf[..n]);
                                let first_line = payload.lines().next().unwrap_or("");
                                eprintln!(
                                    "[PHANTOM SINKHOLE] Intercepted exfiltration payload from {addr}: {first_line}"
                                );
                                if payload.contains("AKIA")
                                    || payload.contains("CANARY")
                                    || payload.contains("token")
                                {
                                    eprintln!(
                                        "[PHANTOM SINKHOLE FORENSICS] Honeypot Canary Token detected in payload!"
                                    );
                                }
                                let http_response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}\n";
                                let _ = socket.write_all(http_response.as_bytes()).await;
                            }
                        }
                    });
                }
            }
        });
    }

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("\n[!] Received SIGINT. Detaching eBPF program and exiting...");
                break;
            }
            _ = drop_interval.tick() => {
                let total_drops: u64 = match dropped_events.get(&0, 0) {
                    Ok(values) => values.iter().sum(),
                    Err(_) => 0,
                };
                if total_drops > 0 {
                    println!("[WARN] Ring buffer overflow detected: {total_drops} dropped execution events.");
                }
            }
            res = async {
                match async_violations.as_mut() {
                    Some(fd) => fd.readable_mut().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Ok(mut guard) = res {
                    let inner = guard.get_inner_mut();
                    while let Some(item) = inner.next() {
                        let event = unsafe { &*(item.as_ptr() as *const ConfinementViolationEvent) };
                        let comm_str = std::str::from_utf8(&event.comm)
                            .unwrap_or("<invalid utf8>")
                            .trim_matches(char::from(0));
                        let bin_str = std::str::from_utf8(&event.binary)
                            .unwrap_or("<invalid utf8>")
                            .trim_matches(char::from(0));

                        eprintln!(
                            "{{\"event\":\"confinement_violation\",\"timestamp_ns\":{},\"agent_pid\":{},\"child_pid\":{},\"comm\":\"{}\",\"binary\":\"{}\"}}",
                            event.timestamp_ns, event.agent_pid, event.child_pid, comm_str, bin_str
                        );

                        if _opt.cryo_freeze && event.agent_pid > 0 {
                            eprintln!(
                                "[CRYO-FREEZE] Confinement violation trapped: {} ({})",
                                bin_str, comm_str
                            );
                            eprintln!(
                                "[CRYO-FREEZE] Process tree suspended in RAM (SIGSTOP): Root PID {} | Worker PID {}",
                                event.agent_pid, event.child_pid
                            );
                            unsafe {
                                libc::kill(event.child_pid as libc::pid_t, libc::SIGSTOP);
                                libc::kill(event.agent_pid as libc::pid_t, libc::SIGSTOP);
                            }
                        } else if _opt.kill_on_violation && event.agent_pid > 0 {
                            eprintln!(
                                "[KILL-SWITCH] Terminating fenced root agent session PID {} with SIGKILL...",
                                event.agent_pid
                            );
                            unsafe {
                                libc::kill(event.agent_pid as libc::pid_t, libc::SIGKILL);
                            }
                        }
                    }
                    guard.clear_ready();
                }
            }
            guard = async_ring_buf.readable_mut() => {
                let mut guard = guard?;
                let inner = guard.get_inner_mut();

                while let Some(item) = inner.next() {
                    let event = unsafe { &*(item.as_ptr() as *const ProcessExecEvent) };
                    let time_str = format_time();
                    let comm_str = std::str::from_utf8(&event.comm)
                        .unwrap_or("<invalid utf8>")
                        .trim_matches(char::from(0));

                    let raw_len = if event.args_len > 0 {
                        event.args_len.min(MAX_ARGS_LEN)
                    } else {
                        event.args.iter().position(|&b| b == 0).unwrap_or(MAX_ARGS_LEN)
                    };

                    let args_str = std::str::from_utf8(&event.args[..raw_len])
                        .unwrap_or("<invalid utf8>")
                        .trim_matches(char::from(0));

                    let args_display = if args_str.is_empty() {
                        comm_str
                    } else {
                        args_str
                    };

                    println!(
                        "[{time_str}] PID: {} | PPID: {} | COMM: {} | ARGS: {}",
                        event.pid, event.ppid, comm_str, args_display
                    );
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}
