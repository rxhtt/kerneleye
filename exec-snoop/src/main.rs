use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    fs::OpenOptions,
    io::Write,
    sync::Mutex,
    time::{Duration, Instant},
};

use aya::{
    Btf,
    maps::{Array, HashMap as BpfHashMap, PerCpuArray, RingBuf},
    programs::{Lsm, TracePoint},
};
use clap::{Parser, Subcommand};
use exec_snoop_common::{ConfinementViolationEvent, MAX_ARGS_LEN, ProcessExecEvent};
use tokio::signal;

#[derive(Debug, Parser)]
#[command(
    name = "kerneleye",
    about = "Zero-container Linux eBPF LSM process isolation and network egress denial for autonomous AI agents",
    version = "0.2.0"
)]
struct Opt {
    #[command(subcommand)]
    subcmd: Option<Commands>,

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

    /// Path to flight recorder immutable JSONL audit log.
    #[arg(long = "audit-log", value_name = "PATH")]
    audit_log: Option<String>,

    /// Sanitize high-risk credentials (AWS_*, OPENAI_*, GITHUB_*, etc.) from child process environment.
    #[arg(long = "scrub-env")]
    scrub_env: bool,

    /// Comma-separated list of environment variable names to preserve when --scrub-env is active.
    #[arg(long = "allow-env", default_value = "PATH,HOME,USER,SHELL,TERM,LANG")]
    allow_env: String,

    /// Suppress verbose process execution trace in runner mode.
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// Trailing command to execute directly under kernel confinement: kerneleye [OPTIONS] -- <CMD> [ARGS...]
    #[arg(last = true)]
    trailing_cmd: Vec<String>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Execute a command directly inside zero-race kernel confinement: kerneleye run -- <CMD> [ARGS...]
    Run {
        /// Command and arguments to execute.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Attach live to an existing running process tree and dynamically adopt it into the kernel fence.
    Attach {
        /// Process ID (PID) of the target agent or worker process.
        pid: u32,
    },
}

struct FlightRecorder {
    file: Option<Mutex<std::fs::File>>,
}

impl FlightRecorder {
    fn new(path: Option<&str>) -> Result<Self, std::io::Error> {
        let file = match path {
            Some(p) => {
                let f = OpenOptions::new().create(true).append(true).open(p)?;
                Some(Mutex::new(f))
            }
            None => None,
        };
        Ok(Self { file })
    }

    fn log(&self, record: &str) {
        if let Some(ref m) = self.file {
            if let Ok(mut f) = m.lock() {
                let _ = writeln!(f, "{record}");
                let _ = f.flush();
            }
        }
    }
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0C' => out.push_str("\\f"),
            c if c < ' ' => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn sanitize_environment(allow_list_str: &str) {
    let allowed: HashSet<String> = allow_list_str
        .split(',')
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .collect();

    let sensitive_prefixes = [
        "AWS_",
        "OPENAI_",
        "ANTHROPIC_",
        "GEMINI_",
        "GITHUB_",
        "GH_",
        "GITLAB_",
        "SLACK_",
        "DISCORD_",
        "STRIPE_",
        "AZURE_",
        "DATABASE_",
        "MONGO_",
        "REDIS_",
    ];

    let sensitive_suffixes = [
        "_KEY",
        "_SECRET",
        "_TOKEN",
        "_PASSWORD",
        "_PASS",
        "_CREDENTIALS",
        "_AUTH",
    ];

    let mut to_remove = Vec::new();
    for (key, _) in std::env::vars() {
        let upper = key.to_uppercase();
        if allowed.contains(&upper) {
            continue;
        }

        let is_sensitive = sensitive_prefixes.iter().any(|p| upper.starts_with(p))
            || sensitive_suffixes.iter().any(|s| upper.ends_with(s))
            || upper == "SSH_AUTH_SOCK"
            || upper == "SSH_AGENT_PID";

        if is_sensitive {
            to_remove.push(key);
        }
    }

    for key in to_remove {
        unsafe {
            std::env::remove_var(&key);
        }
    }
}

fn find_process_tree(target_pid: u32) -> HashSet<u32> {
    let mut tree = HashSet::new();
    tree.insert(target_pid);

    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return tree,
    };

    let mut parent_map: HashMap<u32, u32> = HashMap::new();

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if let Ok(pid) = name_str.parse::<u32>() {
            let stat_path = format!("/proc/{pid}/stat");
            if let Ok(content) = std::fs::read_to_string(&stat_path) {
                if let Some(idx) = content.rfind(')') {
                    let rest = content[idx + 1..].trim();
                    let fields: Vec<&str> = rest.split_whitespace().collect();
                    if fields.len() > 1 {
                        if let Ok(ppid) = fields[1].parse::<u32>() {
                            parent_map.insert(pid, ppid);
                        }
                    }
                }
            }
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for (&pid, &ppid) in &parent_map {
            if tree.contains(&ppid) && tree.insert(pid) {
                changed = true;
            }
        }
    }

    tree
}

struct SessionStats {
    start_time: Instant,
    total_execs: u64,
    unique_pids: HashSet<u32>,
    total_violations: u64,
    blocked_binaries: HashMap<String, u64>,
    blocked_files: HashMap<String, u64>,
    network_drops: u64,
    kill_triggered: bool,
    cryo_triggered: bool,
}

fn truncate_pad(s: &str, width: usize) -> String {
    if s.len() > width {
        let mut end = width.saturating_sub(3);
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    } else {
        format!("{:<width$}", s, width = width)
    }
}

fn print_scorecard(stats: &SessionStats, exit_code: Option<i32>) {
    let elapsed = stats.start_time.elapsed().as_secs_f64();
    let status_str = if stats.kill_triggered {
        "KILL-SWITCH ENGAGED"
    } else if stats.cryo_triggered {
        "CRYO-FREEZE SUSPENDED"
    } else if stats.total_violations > 0 {
        "CONFINEMENT PRESERVED (VIOLATIONS BLOCKED)"
    } else {
        "CLEAN EXECUTION (ZERO VIOLATIONS)"
    };

    let bin_summary = if stats.blocked_binaries.is_empty() {
        "0".to_string()
    } else {
        let total: u64 = stats.blocked_binaries.values().sum();
        let mut parts: Vec<String> = stats
            .blocked_binaries
            .iter()
            .map(|(b, c)| format!("{b}: {c}"))
            .collect();
        parts.sort();
        format!("{total} [{}]", parts.join(", "))
    };

    let file_summary = if stats.blocked_files.is_empty() {
        "0".to_string()
    } else {
        let total: u64 = stats.blocked_files.values().sum();
        let mut parts: Vec<String> = stats
            .blocked_files
            .iter()
            .map(|(f, c)| format!("{f}: {c}"))
            .collect();
        parts.sort();
        format!("{total} [{}]", parts.join(", "))
    };

    let exit_status_str = match exit_code {
        Some(code) => format!("{code}"),
        None => "N/A (Stopped by signal)".to_string(),
    };

    eprintln!("\n┌────────────────────────────────────────────────────────────────────────┐");
    eprintln!("│                       KERNELEYE SECURITY SCORECARD                     │");
    eprintln!("├────────────────────────────────────────────────────────────────────────┤");
    eprintln!("│ Elapsed Session Time        : {:<40.2}s │", elapsed);
    eprintln!(
        "│ Total Execs Intercepted     : {} │",
        truncate_pad(&stats.total_execs.to_string(), 42)
    );
    eprintln!(
        "│ Unique Processes Tracked    : {} │",
        truncate_pad(&stats.unique_pids.len().to_string(), 42)
    );
    eprintln!(
        "│ Total Confinement Violations : {} │",
        truncate_pad(&stats.total_violations.to_string(), 41)
    );
    eprintln!(
        "│ Blocked Binary Executions   : {} │",
        truncate_pad(&bin_summary, 42)
    );
    eprintln!(
        "│ Blocked File Accesses       : {} │",
        truncate_pad(&file_summary, 42)
    );
    eprintln!(
        "│ Blocked Network Drops       : {} │",
        truncate_pad(&stats.network_drops.to_string(), 42)
    );
    eprintln!(
        "│ Child Process Exit Status   : {} │",
        truncate_pad(&exit_status_str, 42)
    );
    eprintln!(
        "│ Security Posture            : {} │",
        truncate_pad(status_str, 42)
    );
    eprintln!("└────────────────────────────────────────────────────────────────────────┘\n");
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
    let opt = Opt::parse();

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
            let val: u8 = if opt.audit_only { 1 } else { 0 };
            let _ = audit_map.set(0, val, 0);
            if opt.audit_only {
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
        if let Ok(mut blocked_map) = BpfHashMap::<_, [u8; 16], u8>::try_from(map) {
            for raw_name in opt.block.split(',') {
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
            println!("[+] Populated BLOCKED_BINARIES policy: {}", opt.block);
        }
    }

    if let Some(map) = bpf.map_mut("BLOCKED_FILES") {
        if let Ok(mut blocked_map) = BpfHashMap::<_, [u8; 16], u8>::try_from(map) {
            for raw_name in opt.block_files.split(',') {
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
            println!("[+] Populated BLOCKED_FILES policy: {}", opt.block_files);
        }
    }

    let mut protected_agent_pids: BpfHashMap<_, u32, u32> = BpfHashMap::try_from(
        bpf.map_mut("PROTECTED_AGENT_PIDS")
            .ok_or("PROTECTED_AGENT_PIDS map not found")?,
    )?;

    // Determine target execution mode: Runner, Attach, or Manual Fence PID
    let runner_command = match &opt.subcmd {
        Some(Commands::Run { command }) => Some(command.clone()),
        _ if !opt.trailing_cmd.is_empty() => Some(opt.trailing_cmd.clone()),
        _ => None,
    };

    let attach_pid = match &opt.subcmd {
        Some(Commands::Attach { pid }) => Some(*pid),
        _ => None,
    };

    let mut runner_child_pid: Option<u32> = None;
    let (exit_tx, mut exit_rx) = tokio::sync::oneshot::channel::<i32>();

    if let Some(ref cmd_args) = runner_command {
        if cmd_args.is_empty() {
            return Err("No command specified to run".into());
        }

        let mut pipefd = [0i32; 2];
        if unsafe { libc::pipe(pipefd.as_mut_ptr()) } != 0 {
            return Err("Failed to create synchronization pipe for runner".into());
        }
        let read_fd = pipefd[0];
        let write_fd = pipefd[1];

        let scrub = opt.scrub_env;
        let allow_env_str = opt.allow_env.clone();
        let cmd_to_exec = cmd_args.clone();

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err("Failed to fork runner process".into());
        }

        if pid == 0 {
            // --- CHILD PROCESS ---
            unsafe {
                libc::close(write_fd);
                let mut syn = [0u8; 1];
                let n = libc::read(read_fd, syn.as_mut_ptr() as *mut libc::c_void, 1);
                libc::close(read_fd);
                if n <= 0 {
                    libc::_exit(127);
                }
            }

            if scrub {
                sanitize_environment(&allow_env_str);
            }

            let c_cmd = match std::ffi::CString::new(cmd_to_exec[0].as_str()) {
                Ok(s) => s,
                Err(_) => unsafe { libc::_exit(127) },
            };

            let c_args: Vec<std::ffi::CString> = cmd_to_exec
                .iter()
                .map(|s| std::ffi::CString::new(s.as_str()).unwrap_or_default())
                .collect();
            let mut c_ptrs: Vec<*const libc::c_char> = c_args.iter().map(|s| s.as_ptr()).collect();
            c_ptrs.push(std::ptr::null());

            unsafe {
                libc::execvp(c_cmd.as_ptr(), c_ptrs.as_ptr());
                libc::perror(b"kerneleye execvp\0".as_ptr() as *const libc::c_char);
                libc::_exit(127);
            }
        }

        // --- PARENT PROCESS ---
        let child_pid = pid as u32;
        unsafe {
            libc::close(read_fd);
        }

        // Immediately fence child_pid in kernel map BEFORE unlocking child!
        protected_agent_pids.insert(child_pid, 1, 0)?;
        println!(
            "[+] Zero-race confinement: Fenced target PID {child_pid} inserted into PROTECTED_AGENT_PIDS prior to exec"
        );

        // Unlock child to execute execvp
        let syn = [1u8; 1];
        unsafe {
            libc::write(write_fd, syn.as_ptr() as *const libc::c_void, 1);
            libc::close(write_fd);
        }

        runner_child_pid = Some(child_pid);

        // Spawn OS thread to wait on child process exit
        std::thread::spawn(move || {
            let mut status: i32 = 0;
            let ret = unsafe { libc::waitpid(child_pid as libc::pid_t, &mut status, 0) };
            let code = if ret > 0 {
                if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else if libc::WIFSIGNALED(status) {
                    128 + libc::WTERMSIG(status)
                } else {
                    1
                }
            } else {
                1
            };
            let _ = exit_tx.send(code);
        });
    }

    if let Some(target_pid) = attach_pid {
        let tree = find_process_tree(target_pid);
        let count = tree.len();
        for &pid in &tree {
            let _ = protected_agent_pids.insert(pid, 1, 0);
        }
        println!(
            "[+] Dynamic Attach: Target PID {target_pid} and {count} process tree descendants adopted into kernel fence"
        );
    }

    for &pid in &opt.fence_pid {
        protected_agent_pids.insert(pid, 1, 0)?;
        println!("[+] Kernel map populated: PID {pid} fenced.");
    }

    if runner_child_pid.is_none() && attach_pid.is_none() && opt.fence_pid.is_empty() {
        println!("[i] No target specified. Running telemetry without agent restrictions.");
    }

    let flight_recorder = FlightRecorder::new(opt.audit_log.as_deref())?;
    if let Some(ref path) = opt.audit_log {
        println!("[+] Flight Recorder active: Streaming audit trail to {path}");
        let init_log = format!(
            "{{\"event\":\"flight_recorder_start\",\"timestamp\":\"{}\",\"block\":\"{}\",\"block_files\":\"{}\"}}",
            format_time(),
            escape_json(&opt.block),
            escape_json(&opt.block_files)
        );
        flight_recorder.log(&init_log);
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
    drop_interval.tick().await;

    if opt.phantom_sink {
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

    let mut stats = SessionStats {
        start_time: Instant::now(),
        total_execs: 0,
        unique_pids: HashSet::new(),
        total_violations: 0,
        blocked_binaries: HashMap::new(),
        blocked_files: HashMap::new(),
        network_drops: 0,
        kill_triggered: false,
        cryo_triggered: false,
    };

    let blocked_files_set: HashSet<String> = opt
        .block_files
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let mut final_exit_code: Option<i32> = None;

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("\n[!] Received SIGINT. Detaching eBPF program and exiting...");
                if let Some(cpid) = runner_child_pid {
                    unsafe {
                        libc::kill(cpid as libc::pid_t, libc::SIGTERM);
                    }
                }
                break;
            }
            code_res = &mut exit_rx, if runner_child_pid.is_some() => {
                if let Ok(code) = code_res {
                    final_exit_code = Some(code);
                }
                // Brief pause to allow kernel ring buffer to drain final events
                tokio::time::sleep(Duration::from_millis(50)).await;
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

                        stats.total_violations += 1;
                        if bin_str.starts_with("socket_") {
                            stats.network_drops += 1;
                        } else if bin_str.starts_with("inode_") || bin_str == "file_open" || blocked_files_set.contains(bin_str) {
                            *stats.blocked_files.entry(bin_str.to_string()).or_insert(0) += 1;
                        } else {
                            *stats.blocked_binaries.entry(bin_str.to_string()).or_insert(0) += 1;
                        }

                        let action_str = if opt.cryo_freeze {
                            stats.cryo_triggered = true;
                            "cryo_freeze"
                        } else if opt.kill_on_violation {
                            stats.kill_triggered = true;
                            "kill_switch"
                        } else if opt.audit_only {
                            "audited"
                        } else {
                            "blocked"
                        };

                        eprintln!(
                            "{{\"event\":\"confinement_violation\",\"timestamp_ns\":{},\"agent_pid\":{},\"child_pid\":{},\"comm\":\"{}\",\"binary\":\"{}\",\"action\":\"{}\"}}",
                            event.timestamp_ns, event.agent_pid, event.child_pid, comm_str, bin_str, action_str
                        );

                        let violation_log = format!(
                            "{{\"ts_ns\":{},\"event\":\"violation\",\"agent_pid\":{},\"child_pid\":{},\"comm\":\"{}\",\"binary\":\"{}\",\"action\":\"{}\"}}",
                            event.timestamp_ns, event.agent_pid, event.child_pid, escape_json(comm_str), escape_json(bin_str), action_str
                        );
                        flight_recorder.log(&violation_log);

                        if opt.cryo_freeze && event.agent_pid > 0 {
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
                        } else if opt.kill_on_violation && event.agent_pid > 0 {
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

                    stats.total_execs += 1;
                    stats.unique_pids.insert(event.pid);

                    let exec_log = format!(
                        "{{\"ts\":\"{}\",\"event\":\"exec\",\"pid\":{},\"ppid\":{},\"comm\":\"{}\",\"args\":\"{}\"}}",
                        time_str, event.pid, event.ppid, escape_json(comm_str), escape_json(args_display)
                    );
                    flight_recorder.log(&exec_log);

                    if !opt.quiet {
                        println!(
                            "[{time_str}] PID: {} | PPID: {} | COMM: {} | ARGS: {}",
                            event.pid, event.ppid, comm_str, args_display
                        );
                    }
                }
                guard.clear_ready();
            }
        }
    }

    print_scorecard(&stats, final_exit_code);

    let summary_log = format!(
        "{{\"event\":\"session_summary\",\"elapsed_secs\":{:.2},\"total_execs\":{},\"unique_pids\":{},\"total_violations\":{},\"exit_code\":{}}}",
        stats.start_time.elapsed().as_secs_f64(),
        stats.total_execs,
        stats.unique_pids.len(),
        stats.total_violations,
        final_exit_code.unwrap_or(0)
    );
    flight_recorder.log(&summary_log);

    if let Some(code) = final_exit_code {
        std::process::exit(code);
    }

    Ok(())
}
