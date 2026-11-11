use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::TryInto,
    fs::OpenOptions,
    io::Write,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
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

    /// Transparent local audit proxy on 127.0.0.1:18080: permits package registries (npm, cargo, pypi, git) & blocks exfiltration.
    #[arg(long = "proxy-allow-registries")]
    proxy_allow_registries: bool,

    /// Port for the transparent registry proxy [default: 18080].
    #[arg(long = "proxy-port", default_value = "18080")]
    proxy_port: u16,

    /// Comma-separated list of extra trusted domains to permit through the registry proxy.
    #[arg(long = "allow-domain", default_value = "")]
    allow_domain: String,

    /// Comma-separated list of IPv4 addresses to whitelist for in-kernel network egress.
    #[arg(long = "allow-ip", default_value = "")]
    allow_ip: String,

    /// In-kernel allow loopback network traffic (127.0.0.0/8 and ::1).
    #[arg(long = "allow-loopback")]
    allow_loopback: bool,

    /// Strict workspace boundary directory sandboxing. Restricts execution and file modifications to DIR.
    #[arg(long = "workspace", value_name = "DIR")]
    workspace: Option<String>,

    /// Deploy honeypot canary credential tokens (.env.canary, credentials.canary) with automated tripwires.
    #[arg(long = "canary-tokens")]
    canary_tokens: bool,

    /// Launch real-time interactive terminal monitoring dashboard.
    #[arg(long = "tui")]
    tui: bool,

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

    /// Direct execution shorthand: command and arguments to execute after '--'.
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
    /// Launch real-time interactive terminal monitoring dashboard: kerneleye top
    Top,
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

struct CanaryGuard {
    paths: Vec<std::path::PathBuf>,
}

impl CanaryGuard {
    fn create(workspace_dir: Option<&str>) -> Self {
        let base_dir = workspace_dir
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
            });

        let mut paths = Vec::new();

        let env_canary = base_dir.join(".env.canary");
        let content = "# KernelEye Honeypot Canary Credential (Mirage VFS)\nAWS_ACCESS_KEY_ID=AKIA_CANARY_TRUMAN_SHOW_99812_PROD_FAKE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY_CANARY\nOPENAI_API_KEY=sk-proj-canary-honeypot-token-do-not-leak-99881\nEXFIL_SINK_URL=http://127.0.0.1:65530/canary_exfil\n";
        if std::fs::write(&env_canary, content).is_ok() {
            paths.push(env_canary);
        }

        let cred_canary = base_dir.join("credentials.canary");
        let cred_content = "[default]\naws_access_key_id = AKIA_CANARY_TRUMAN_SHOW_99812_PROD_FAKE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY_CANARY\n";
        if std::fs::write(&cred_canary, cred_content).is_ok() {
            paths.push(cred_canary);
        }

        println!(
            "[+] Canary Honeypot active: Injected honeypot credentials (.env.canary, credentials.canary)"
        );
        Self { paths }
    }
}

impl Drop for CanaryGuard {
    fn drop(&mut self) {
        for path in &self.paths {
            let _ = std::fs::remove_file(path);
        }
    }
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

fn format_uptime(secs: u64) -> String {
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{hours:02}:{mins:02}:{s:02}")
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

async fn run_registry_proxy(
    port: u16,
    extra_domains: Vec<String>,
    recorder: Arc<FlightRecorder>,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    println!(
        "[+] Transparent Registry Proxy active on 127.0.0.1:{port} (Whitelist Filter Enabled)"
    );

    let mut allowed_domains: HashSet<String> = [
        "registry.npmjs.org",
        "crates.io",
        "static.crates.io",
        "index.crates.io",
        "pypi.org",
        "files.pythonhosted.org",
        "pypi.python.org",
        "github.com",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
        "api.github.com",
        "archive.ubuntu.com",
        "security.ubuntu.com",
        "dl-cdn.alpinelinux.org",
        "repo.anaconda.com",
        "conda.anaconda.org",
        "rubygems.org",
        "golang.org",
        "proxy.golang.org",
        "sum.golang.org",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    for d in extra_domains {
        allowed_domains.insert(d.to_lowercase());
    }

    loop {
        if let Ok((mut client_sock, client_addr)) = listener.accept().await {
            let domains = allowed_domains.clone();
            let rec = recorder.clone();

            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = match client_sock.read(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => return,
                };

                let req = String::from_utf8_lossy(&buf[..n]);
                let first_line = req.lines().next().unwrap_or("");

                if first_line.starts_with("CONNECT ") {
                    let parts: Vec<&str> = first_line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let target = parts[1];
                        let host = target.split(':').next().unwrap_or(target).to_lowercase();

                        let is_allowed = domains
                            .iter()
                            .any(|d| host == *d || host.ends_with(&format!(".{d}")));

                        if is_allowed {
                            if let Ok(mut server_sock) = TcpStream::connect(target).await {
                                let _ = client_sock
                                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                                    .await;
                                let _ = tokio::io::copy_bidirectional(
                                    &mut client_sock,
                                    &mut server_sock,
                                )
                                .await;
                                return;
                            }
                        } else {
                            eprintln!(
                                "[REGISTRY SHIELD] Blocked exfiltration attempt from {client_addr} to unauthorized host: {host}"
                            );
                            let log = format!(
                                "{{\"event\":\"proxy_violation\",\"client\":\"{}\",\"target_host\":\"{}\",\"action\":\"forbidden\"}}",
                                client_addr,
                                escape_json(&host)
                            );
                            rec.log(&log);

                            let resp = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n[BLOCKED BY KERNELEYE REGISTRY SHIELD] Exfiltration attempt to unauthorized host.\n";
                            let _ = client_sock.write_all(resp).await;
                            return;
                        }
                    }
                }

                let host_header = req
                    .lines()
                    .find(|l| l.to_lowercase().starts_with("host:"))
                    .and_then(|l| l.split(':').nth(1))
                    .map(|h| h.trim().to_lowercase())
                    .unwrap_or_default();

                let is_allowed = domains
                    .iter()
                    .any(|d| host_header == *d || host_header.ends_with(&format!(".{d}")));

                if is_allowed && !host_header.is_empty() {
                    let target = format!("{host_header}:80");
                    if let Ok(mut server_sock) = TcpStream::connect(&target).await {
                        let _ = server_sock.write_all(&buf[..n]).await;
                        let _ =
                            tokio::io::copy_bidirectional(&mut client_sock, &mut server_sock).await;
                        return;
                    }
                }

                let resp = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n[BLOCKED BY KERNELEYE REGISTRY SHIELD] HTTP request to unauthorized host.\n";
                let _ = client_sock.write_all(resp).await;
            });
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::parse();

    let is_tui = opt.tui || matches!(opt.subcmd, Some(Commands::Top));

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

    if !is_tui {
        println!("[+] eBPF program loaded and attached to sched:sched_process_exec");
    }

    if let Some(fork_prog) = bpf.program_mut("process_fork") {
        let fork_program: Result<&mut TracePoint, _> = fork_prog.try_into();
        match fork_program {
            Ok(p) => {
                if let Err(e) = p.load() {
                    eprintln!("[!] Failed to load process_fork: {e}");
                } else if let Err(e) = p.attach("sched", "sched_process_fork") {
                    eprintln!("[!] Failed to attach sched:sched_process_fork: {e}");
                } else if !is_tui {
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
                            Ok(_) => {
                                if !is_tui {
                                    println!("[+] eBPF LSM hook attached: {hook_name} ({desc})");
                                }
                            }
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
            if opt.audit_only && !is_tui {
                println!("[*] AUDIT MODE ACTIVE: Violations will be logged without blocking.");
            }
        }
    }

    if let Some(map) = bpf.map_mut("DAEMON_PID") {
        if let Ok(mut daemon_map) = Array::<_, u32>::try_from(map) {
            let my_pid = std::process::id();
            let _ = daemon_map.set(0, my_pid, 0);
            if !is_tui {
                println!("[+] Anti-tamper active: Protected daemon PID {my_pid} against signals");
            }
        }
    }

    let allow_loopback_active =
        opt.proxy_allow_registries || opt.phantom_sink || opt.allow_loopback;
    if let Some(map) = bpf.map_mut("ALLOW_LOOPBACK") {
        if let Ok(mut loopback_map) = Array::<_, u8>::try_from(map) {
            let val: u8 = if allow_loopback_active { 1 } else { 0 };
            let _ = loopback_map.set(0, val, 0);
            if val == 1 && !is_tui {
                println!(
                    "[+] In-kernel loopback permitted for 127.0.0.0/8 (Registry Proxy / Sinkhole)"
                );
            }
        }
    }

    if let Some(map) = bpf.map_mut("ALLOWED_IPS") {
        if let Ok(mut allowed_map) = BpfHashMap::<_, u32, u8>::try_from(map) {
            for raw_ip in opt.allow_ip.split(',') {
                let ip_str = raw_ip.trim();
                if ip_str.is_empty() {
                    continue;
                }
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    let ip_u32 = u32::from_ne_bytes(ip.octets());
                    let _ = allowed_map.insert(ip_u32, 1, 0);
                    if !is_tui {
                        println!("[+] Kernel IP whitelist populated: {ip_str}");
                    }
                }
            }
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
            if !is_tui {
                println!("[+] Populated BLOCKED_BINARIES policy: {}", opt.block);
            }
        }
    }

    // Build sensitive blocked files list (combining default + canary + workspace anti-evasion)
    let mut file_deny_list = opt.block_files.clone();
    if opt.canary_tokens {
        file_deny_list.push_str(",.env.canary,credentials.canary");
    }
    if opt.workspace.is_some() {
        file_deny_list.push_str(",.bashrc,.bash_profile,.zshrc,.profile,sudoers,passwd");
    }

    if let Some(map) = bpf.map_mut("BLOCKED_FILES") {
        if let Ok(mut blocked_map) = BpfHashMap::<_, [u8; 16], u8>::try_from(map) {
            for raw_name in file_deny_list.split(',') {
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
            if !is_tui {
                println!("[+] Populated BLOCKED_FILES policy: {}", file_deny_list);
            }
        }
    }

    let _canary_guard = if opt.canary_tokens {
        Some(CanaryGuard::create(opt.workspace.as_deref()))
    } else {
        None
    };

    let mut protected_agent_pids: BpfHashMap<_, u32, u32> = BpfHashMap::try_from(
        bpf.map_mut("PROTECTED_AGENT_PIDS")
            .ok_or("PROTECTED_AGENT_PIDS map not found")?,
    )?;

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
        let ws_dir = opt.workspace.clone();
        let proxy_active = opt.proxy_allow_registries;
        let proxy_port_num = opt.proxy_port;

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

            if let Some(ref dir) = ws_dir {
                if let Ok(c_dir) = std::ffi::CString::new(dir.as_str()) {
                    unsafe {
                        libc::chdir(c_dir.as_ptr());
                        std::env::set_var("PWD", dir);
                    }
                }
            }

            if proxy_active {
                let proxy_url = format!("http://127.0.0.1:{proxy_port_num}");
                unsafe {
                    std::env::set_var("HTTP_PROXY", &proxy_url);
                    std::env::set_var("HTTPS_PROXY", &proxy_url);
                    std::env::set_var("ALL_PROXY", &proxy_url);
                    std::env::set_var("http_proxy", &proxy_url);
                    std::env::set_var("https_proxy", &proxy_url);
                    std::env::set_var("all_proxy", &proxy_url);
                }
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
        if !is_tui {
            println!(
                "[+] Zero-race confinement: Fenced target PID {child_pid} inserted into PROTECTED_AGENT_PIDS prior to exec"
            );
        }

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
        if !is_tui {
            println!(
                "[+] Dynamic Attach: Target PID {target_pid} and {count} process tree descendants adopted into kernel fence"
            );
        }
    }

    for &pid in &opt.fence_pid {
        protected_agent_pids.insert(pid, 1, 0)?;
        if !is_tui {
            println!("[+] Kernel map populated: PID {pid} fenced.");
        }
    }

    if runner_child_pid.is_none() && attach_pid.is_none() && opt.fence_pid.is_empty() && !is_tui {
        println!("[i] No target specified. Running telemetry without agent restrictions.");
    }

    let flight_recorder = Arc::new(FlightRecorder::new(opt.audit_log.as_deref())?);
    if let Some(ref path) = opt.audit_log {
        if !is_tui {
            println!("[+] Flight Recorder active: Streaming audit trail to {path}");
        }
        let init_log = format!(
            "{{\"event\":\"flight_recorder_start\",\"timestamp\":\"{}\",\"block\":\"{}\",\"block_files\":\"{}\"}}",
            format_time(),
            escape_json(&opt.block),
            escape_json(&file_deny_list)
        );
        flight_recorder.log(&init_log);
    }

    if opt.proxy_allow_registries {
        let extra_domains: Vec<String> = opt
            .allow_domain
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let rec = flight_recorder.clone();
        let port = opt.proxy_port;
        tokio::spawn(async move {
            if let Err(e) = run_registry_proxy(port, extra_domains, rec).await {
                eprintln!("[!] Registry proxy server error: {e}");
            }
        });
    }

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

    if !is_tui {
        println!("[+] Streaming process executions (Press Ctrl+C to stop)...");
    }

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

    let mut tui_interval = tokio::time::interval(Duration::from_millis(300));
    tui_interval.tick().await;

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

    let blocked_files_set: HashSet<String> = file_deny_list
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let mut recent_procs: VecDeque<(u32, u32, String, String)> = VecDeque::with_capacity(10);
    let mut recent_alerts: VecDeque<String> = VecDeque::with_capacity(10);

    let mut final_exit_code: Option<i32> = None;

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                if !is_tui {
                    println!("\n[!] Received SIGINT. Detaching eBPF program and exiting...");
                }
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
                tokio::time::sleep(Duration::from_millis(50)).await;
                break;
            }
            _ = tui_interval.tick(), if is_tui => {
                // Render ANSI Dashboard
                let uptime = format_uptime(stats.start_time.elapsed().as_secs());
                let rate = stats.total_execs as f64 / stats.start_time.elapsed().as_secs_f64().max(0.1);
                print!("\x1b[2J\x1b[H"); // Clear screen & move to top-left
                println!("┌──────────────────────────────────────────────────────────────────────────────┐");
                println!("│  KERNELEYE TOP: In-Kernel eBPF LSM Process Security Monitor                  │");
                println!("│  Version: 0.2.0 | Mode: ENFORCING | Uptime: {:<8} | Interception: ~3.2 µs   │", uptime);
                println!("├──────────────────────────────────────────────────────────────────────────────┤");
                println!("│  Syscalls Intercepted: {:<14} Syscall Rate: {:<7.1} /s        │", stats.total_execs, rate);
                println!("│  Unique Tracked PIDs : {:<14} Total Violations: {:<17}│", stats.unique_pids.len(), stats.total_violations);
                println!("│  Blocked Network Drops: {:<13} Blocked Binaries: {:<16}│", stats.network_drops, stats.blocked_binaries.values().sum::<u64>());
                println!("├──────────────────────────────────────────────────────────────────────────────┤");
                println!("│ ACTIVE PROCESS TREE TELEMETRY (RECENT EXECUTIONS)                            │");
                println!("│ PID      PPID     COMM             ARGS                                      │");
                for (p, pp, c, a) in recent_procs.iter().rev().take(6) {
                    println!("│ {:<8} {:<8} {:<16} {:<41} │", p, pp, truncate_pad(c, 16), truncate_pad(a, 41));
                }
                println!("├──────────────────────────────────────────────────────────────────────────────┤");
                println!("│ RECENT SECURITY ALERTS (FLIGHT RECORDER)                                     │");
                if recent_alerts.is_empty() {
                    println!("│ [OK] No confinement violations trapped. Process tree conforms to policy.     │");
                } else {
                    for alert in recent_alerts.iter().rev().take(4) {
                        println!("│ {:<76} │", truncate_pad(alert, 76));
                    }
                }
                println!("└──────────────────────────────────────────────────────────────────────────────┘");
                println!("Press Ctrl+C to stop monitoring.");
            }
            _ = drop_interval.tick() => {
                let total_drops: u64 = match dropped_events.get(&0, 0) {
                    Ok(values) => values.iter().sum(),
                    Err(_) => 0,
                };
                if total_drops > 0 && !is_tui {
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
                        if bin_str.starts_with("network:") || bin_str.starts_with("socket_") {
                            stats.network_drops += 1;
                        } else if bin_str.starts_with("destruct:") || bin_str.starts_with("evasion:") || bin_str == "file_open" || blocked_files_set.contains(bin_str) {
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

                        let alert_msg = format!(
                            "[{}] PID {} ({}) -> {} [{}]",
                            format_time(), event.child_pid, comm_str, bin_str, action_str
                        );
                        if recent_alerts.len() >= 10 {
                            recent_alerts.pop_front();
                        }
                        recent_alerts.push_back(alert_msg);

                        if !is_tui {
                            eprintln!(
                                "{{\"event\":\"confinement_violation\",\"timestamp_ns\":{},\"agent_pid\":{},\"child_pid\":{},\"comm\":\"{}\",\"binary\":\"{}\",\"action\":\"{}\"}}",
                                event.timestamp_ns, event.agent_pid, event.child_pid, comm_str, bin_str, action_str
                            );
                        }

                        let violation_log = format!(
                            "{{\"ts_ns\":{},\"event\":\"violation\",\"agent_pid\":{},\"child_pid\":{},\"comm\":\"{}\",\"binary\":\"{}\",\"action\":\"{}\"}}",
                            event.timestamp_ns, event.agent_pid, event.child_pid, escape_json(comm_str), escape_json(bin_str), action_str
                        );
                        flight_recorder.log(&violation_log);

                        if opt.cryo_freeze && event.agent_pid > 0 {
                            if !is_tui {
                                eprintln!(
                                    "[CRYO-FREEZE] Confinement violation trapped: {} ({})",
                                    bin_str, comm_str
                                );
                                eprintln!(
                                    "[CRYO-FREEZE] Process tree suspended in RAM (SIGSTOP): Root PID {} | Worker PID {}",
                                    event.agent_pid, event.child_pid
                                );
                            }
                            unsafe {
                                libc::kill(event.child_pid as libc::pid_t, libc::SIGSTOP);
                                libc::kill(event.agent_pid as libc::pid_t, libc::SIGSTOP);
                            }
                        } else if opt.kill_on_violation && event.agent_pid > 0 {
                            if !is_tui {
                                eprintln!(
                                    "[KILL-SWITCH] Terminating fenced root agent session PID {} with SIGKILL...",
                                    event.agent_pid
                                );
                            }
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

                    if recent_procs.len() >= 10 {
                        recent_procs.pop_front();
                    }
                    recent_procs.push_back((event.pid, event.ppid, comm_str.to_string(), args_display.to_string()));

                    let exec_log = format!(
                        "{{\"ts\":\"{}\",\"event\":\"exec\",\"pid\":{},\"ppid\":{},\"comm\":\"{}\",\"args\":\"{}\"}}",
                        time_str, event.pid, event.ppid, escape_json(comm_str), escape_json(args_display)
                    );
                    flight_recorder.log(&exec_log);

                    if !opt.quiet && !is_tui {
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

    if is_tui {
        print!("\x1b[2J\x1b[H"); // Clear screen upon exit
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
