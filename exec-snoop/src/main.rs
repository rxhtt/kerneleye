use aya::maps::{HashMap, PerCpuArray, RingBuf};
use aya::programs::{Lsm, TracePoint};
use aya::Btf;
use clap::Parser;
use exec_snoop_common::{ConfinementViolationEvent, ProcessExecEvent, MAX_ARGS_LEN};
use std::convert::TryInto;
use std::time::Duration;
use tokio::signal;

#[derive(Debug, Parser)]
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
    #[arg(long = "block-files", default_value = "id_rsa,id_ed25519,credentials,.env,shadow,authorized_keys")]
    block_files: String,
}

fn format_time() -> String {
    let now = std::time::SystemTime::now();
    let duration = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
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

    if let Some(prog) = bpf.program_mut("bprm_check_security") {
        match Btf::from_sys_fs() {
            Ok(btf) => {
                let lsm_program: Result<&mut Lsm, _> = prog.try_into();
                match lsm_program {
                    Ok(lsm_prog) => match lsm_prog.load("bprm_check_security", &btf) {
                        Ok(()) => match lsm_prog.attach() {
                            Ok(_) => println!("[+] eBPF LSM hook attached to bprm_check_security (blocking configured binaries)"),
                            Err(e) => eprintln!("[!] Failed to attach LSM hook: {e}"),
                        },
                        Err(e) => eprintln!("[!] Failed to load LSM program: {e}"),
                    },
                    Err(e) => eprintln!("[!] Failed to convert program to Lsm: {e}"),
                }
            }
            Err(e) => eprintln!("[!] Failed to read BTF from sysfs: {e}"),
        }
    }

    if let Some(prog) = bpf.program_mut("socket_connect") {
        match Btf::from_sys_fs() {
            Ok(btf) => {
                let lsm_program: Result<&mut Lsm, _> = prog.try_into();
                match lsm_program {
                    Ok(lsm_prog) => match lsm_prog.load("socket_connect", &btf) {
                        Ok(()) => match lsm_prog.attach() {
                            Ok(_) => println!("[+] eBPF LSM hook attached to socket_connect (blocking AF_INET/AF_INET6 egress)"),
                            Err(e) => eprintln!("[!] Failed to attach socket_connect hook: {e}"),
                        },
                        Err(e) => eprintln!("[!] Failed to load socket_connect program: {e}"),
                    },
                    Err(e) => eprintln!("[!] Failed to convert socket_connect to Lsm: {e}"),
                }
            }
            Err(e) => eprintln!("[!] Failed to read BTF from sysfs for socket_connect: {e}"),
        }
    }

    if let Some(prog) = bpf.program_mut("socket_sendmsg") {
        match Btf::from_sys_fs() {
            Ok(btf) => {
                let lsm_program: Result<&mut Lsm, _> = prog.try_into();
                match lsm_program {
                    Ok(lsm_prog) => match lsm_prog.load("socket_sendmsg", &btf) {
                        Ok(()) => match lsm_prog.attach() {
                            Ok(_) => println!("[+] eBPF LSM hook attached to socket_sendmsg (blocking connectionless UDP / egress)"),
                            Err(e) => eprintln!("[!] Failed to attach socket_sendmsg hook: {e}"),
                        },
                        Err(e) => eprintln!("[!] Failed to load socket_sendmsg program: {e}"),
                    },
                    Err(e) => eprintln!("[!] Failed to convert socket_sendmsg to Lsm: {e}"),
                }
            }
            Err(e) => eprintln!("[!] Failed to read BTF from sysfs for socket_sendmsg: {e}"),
        }
    }

    if let Some(prog) = bpf.program_mut("file_open") {
        match Btf::from_sys_fs() {
            Ok(btf) => {
                let lsm_program: Result<&mut Lsm, _> = prog.try_into();
                match lsm_program {
                    Ok(lsm_prog) => match lsm_prog.load("file_open", &btf) {
                        Ok(()) => match lsm_prog.attach() {
                            Ok(_) => println!("[+] eBPF LSM hook attached to file_open (blocking sensitive credential access)"),
                            Err(e) => eprintln!("[!] Failed to attach file_open hook: {e}"),
                        },
                        Err(e) => eprintln!("[!] Failed to load file_open program: {e}"),
                    },
                    Err(e) => eprintln!("[!] Failed to convert file_open to Lsm: {e}"),
                }
            }
            Err(e) => eprintln!("[!] Failed to read BTF from sysfs for file_open: {e}"),
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

    let ring_buf = RingBuf::try_from(
        bpf.take_map("RINGBUF")
            .ok_or("RINGBUF map not found")?,
    )?;
    let mut async_ring_buf = unsafe { tokio::io::unix::AsyncFd::register(ring_buf) }?;

    let violations_buf = bpf.take_map("VIOLATIONS").and_then(|m| RingBuf::try_from(m).ok());
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

                        if _opt.kill_on_violation && event.agent_pid > 0 {
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
