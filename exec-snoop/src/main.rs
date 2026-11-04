use aya::maps::{PerCpuArray, RingBuf};
use aya::programs::{Lsm, TracePoint};
use aya::Btf;
use clap::Parser;
use exec_snoop_common::{ProcessExecEvent, MAX_ARGS_LEN};
use std::convert::TryInto;
use std::time::Duration;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {}

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

    if let Some(prog) = bpf.program_mut("bprm_check_security") {
        match Btf::from_sys_fs() {
            Ok(btf) => {
                let lsm_program: Result<&mut Lsm, _> = prog.try_into();
                match lsm_program {
                    Ok(lsm_prog) => match lsm_prog.load("bprm_check_security", &btf) {
                        Ok(()) => match lsm_prog.attach() {
                            Ok(_) => println!("[+] eBPF LSM hook attached to bprm_check_security (blocking 'curl')"),
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
    println!("[+] Streaming process executions (Press Ctrl+C to stop)...");

    let ring_buf = RingBuf::try_from(
        bpf.take_map("RINGBUF")
            .ok_or("RINGBUF map not found")?,
    )?;
    let mut async_ring_buf = unsafe { tokio::io::unix::AsyncFd::register(ring_buf) }?;

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
