#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{lsm, map, tracepoint},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, TracePointContext},
    EbpfContext,
};
use exec_snoop_common::{ProcessExecEvent, MAX_AGENT_PIDS, MAX_ARGS_LEN};

#[map]
static RINGBUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static DROPPED_EVENTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
static PROTECTED_AGENT_PIDS: HashMap<u32, u32> = HashMap::with_max_entries(MAX_AGENT_PIDS, 0);

#[tracepoint]
pub fn exec_snoop(ctx: TracePointContext) -> u32 {
    match try_exec_snoop(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn process_fork(ctx: TracePointContext) -> u32 {
    let _ = try_process_fork(ctx);
    0
}

fn try_process_fork(ctx: TracePointContext) -> Result<(), u32> {
    let current_tgid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let current_pid = aya_ebpf::helpers::bpf_get_current_pid_tgid() as u32;

    let is_parent_fenced = unsafe {
        PROTECTED_AGENT_PIDS.get(&current_tgid).is_some()
            || PROTECTED_AGENT_PIDS.get(&current_pid).is_some()
            || ctx.read_at::<u32>(12).map(|p| PROTECTED_AGENT_PIDS.get(&p).is_some()).unwrap_or(false)
            || ctx.read_at::<u32>(24).map(|p| PROTECTED_AGENT_PIDS.get(&p).is_some()).unwrap_or(false)
    };

    if is_parent_fenced {
        if let Ok(child) = unsafe { ctx.read_at::<u32>(20) } {
            if child > 0 {
                let _ = PROTECTED_AGENT_PIDS.insert(&child, &1, 0);
            }
        }
        if let Ok(child) = unsafe { ctx.read_at::<u32>(44) } {
            if child > 0 {
                let _ = PROTECTED_AGENT_PIDS.insert(&child, &1, 0);
            }
        }
    }

    Ok(())
}

unsafe fn get_ppid() -> u32 {
    let task = unsafe { aya_ebpf::helpers::bpf_get_current_task() } as *const u8;
    if task.is_null() {
        return 0;
    }

    // Offset of real_parent in task_struct for Linux 7.0.0-31-generic (x86_64) is 2816 bytes
    let parent_task_ptr: *const u8 = match unsafe { aya_ebpf::helpers::bpf_probe_read_kernel(task.add(2816).cast()) } {
        Ok(ptr) => ptr,
        Err(_) => return 0,
    };

    if parent_task_ptr.is_null() {
        return 0;
    }

    // Offset of tgid in task_struct for Linux 7.0.0-31-generic (x86_64) is 2804 bytes
    match unsafe { aya_ebpf::helpers::bpf_probe_read_kernel(parent_task_ptr.add(2804).cast::<u32>()) } {
        Ok(ppid) => ppid,
        Err(_) => 0,
    }
}

fn try_exec_snoop(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let ppid = unsafe { get_ppid() };

    let mut args = [0u8; MAX_ARGS_LEN];
    let mut args_len: usize = 0;

    // In sched:sched_process_exec, offset 8 is __data_loc filename.
    // The lower 16 bits contain the offset relative to the tracepoint context.
    if let Ok(loc) = unsafe { ctx.read_at::<u32>(8) } {
        let offset = (loc & 0xFFFF) as usize;
        if offset > 0 {
            let str_ptr = unsafe { (ctx.as_ptr() as *const u8).add(offset) };
            #[allow(deprecated)]
            if let Ok(len) = unsafe { aya_ebpf::helpers::bpf_probe_read_user_str(str_ptr, &mut args) } {
                args_len = len;
            } else if let Ok(bytes) = unsafe { aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes(str_ptr, &mut args) } {
                args_len = bytes.len();
            }
        }
    }

    if let Some(mut entry) = RINGBUF.reserve::<ProcessExecEvent>(0) {
        let event = ProcessExecEvent {
            pid,
            ppid,
            args_len,
            comm,
            args,
        };
        entry.write(event);
        entry.submit(0);
    } else if let Some(ptr) = DROPPED_EVENTS.get_ptr_mut(0) {
        unsafe { *ptr += 1 };
    }

    Ok(0)
}

fn debug_log(tag: &[u8], pid: u32, ppid: u32, info: &[u8]) {
    if let Some(mut entry) = RINGBUF.reserve::<ProcessExecEvent>(0) {
        let mut comm = [0u8; 16];
        let mut len = 0;
        while len < tag.len() && len < 16 {
            comm[len] = tag[len];
            len += 1;
        }
        let mut args = [0u8; MAX_ARGS_LEN];
        let mut info_len = 0;
        while info_len < info.len() && info_len < MAX_ARGS_LEN {
            args[info_len] = info[info_len];
            info_len += 1;
        }
        entry.write(ProcessExecEvent {
            pid,
            ppid,
            args_len: info_len,
            comm,
            args,
        });
        entry.submit(0);
    }
}

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;
    let ppid = unsafe { get_ppid() };

    let mut is_fenced = unsafe {
        PROTECTED_AGENT_PIDS.get(&tgid).is_some()
            || PROTECTED_AGENT_PIDS.get(&pid).is_some()
            || (ppid > 0 && PROTECTED_AGENT_PIDS.get(&ppid).is_some())
    };

    if !is_fenced {
        let mut task = unsafe { aya_ebpf::helpers::bpf_get_current_task() } as *const u8;
        for _ in 0..4 {
            if task.is_null() {
                break;
            }

            // Offset 2816 is real_parent in task_struct for Linux 7.0.0-31-generic (x86_64)
            let parent = match unsafe { aya_ebpf::helpers::bpf_probe_read_kernel(task.add(2816).cast::<*const u8>()) } {
                Ok(p) => p,
                Err(_) => break,
            };

            if parent.is_null() || parent == task {
                break;
            }

            // Check tgid (offset 2804)
            if let Ok(parent_tgid) = unsafe { aya_ebpf::helpers::bpf_probe_read_kernel(parent.add(2804).cast::<u32>()) } {
                if parent_tgid > 0 && unsafe { PROTECTED_AGENT_PIDS.get(&parent_tgid) }.is_some() {
                    is_fenced = true;
                    break;
                }
                if parent_tgid <= 1 {
                    break;
                }
            }

            // Check pid (offset 2800)
            if let Ok(parent_pid) = unsafe { aya_ebpf::helpers::bpf_probe_read_kernel(parent.add(2800).cast::<u32>()) } {
                if parent_pid > 0 && unsafe { PROTECTED_AGENT_PIDS.get(&parent_pid) }.is_some() {
                    is_fenced = true;
                    break;
                }
            }

            task = parent;
        }
    }

    if is_fenced {
        let _ = PROTECTED_AGENT_PIDS.insert(&tgid, &1, 0);
        let _ = PROTECTED_AGENT_PIDS.insert(&pid, &1, 0);
    } else {
        return 0;
    }

    let mut blocked = false;
    let mut read_ok = false;

    // Check 1: bprm->filename at offset 96
    let bprm_ptr: *const u8 = ctx.arg(0);
    if !bprm_ptr.is_null() {
        if let Ok(filename_ptr) = unsafe {
            aya_ebpf::helpers::bpf_probe_read_kernel(bprm_ptr.add(96).cast::<*const u8>())
        } {
            if !filename_ptr.is_null() {
                let mut buf = [0u8; 64];
                if let Ok(bytes) = unsafe {
                    aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes(filename_ptr, &mut buf)
                } {
                    read_ok = true;
                    debug_log(b"LSM_FENCE_KSTR", pid, ppid, bytes);
                    if is_blocked(bytes) {
                        blocked = true;
                    }
                } else if let Ok(bytes) = unsafe {
                    aya_ebpf::helpers::bpf_probe_read_user_str_bytes(filename_ptr, &mut buf)
                } {
                    read_ok = true;
                    debug_log(b"LSM_FENCE_USTR", pid, ppid, bytes);
                    if is_blocked(bytes) {
                        blocked = true;
                    }
                }
            }
        }

        // Check 2: bprm->file->f_path.dentry->d_name.name
        // bprm + 64 (file) -> file + 64 (f_path) -> f_path + 8 (dentry) -> dentry + 32 (d_name) -> qstr + 8 (name)
        if !blocked {
            if let Ok(file_ptr) = unsafe {
                aya_ebpf::helpers::bpf_probe_read_kernel(bprm_ptr.add(64).cast::<*const u8>())
            } {
                if !file_ptr.is_null() {
                    if let Ok(dentry_ptr) = unsafe {
                        aya_ebpf::helpers::bpf_probe_read_kernel(file_ptr.add(72).cast::<*const u8>())
                    } {
                        if !dentry_ptr.is_null() {
                            if let Ok(name_ptr) = unsafe {
                                aya_ebpf::helpers::bpf_probe_read_kernel(dentry_ptr.add(40).cast::<*const u8>())
                            } {
                                if !name_ptr.is_null() {
                                    let mut buf = [0u8; 32];
                                    if let Ok(bytes) = unsafe {
                                        aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes(name_ptr, &mut buf)
                                    } {
                                        read_ok = true;
                                        debug_log(b"LSM_DENTRY", pid, ppid, bytes);
                                        if is_blocked(bytes) {
                                            blocked = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Check 3: Current task comm
    if !blocked {
        if let Ok(comm) = aya_ebpf::helpers::bpf_get_current_comm() {
            if is_blocked(&comm) {
                blocked = true;
            }
        }
    }

    if !read_ok {
        debug_log(b"LSM_NO_READ", pid, ppid, b"cannot read filename");
    }

    if blocked {
        return -1; // -EPERM
    }

    0
}

#[inline(always)]
fn is_blocked(path: &[u8]) -> bool {
    let mut len = 0;
    while len < path.len() && path[len] != 0 {
        len += 1;
    }
    if len < 4 {
        return false;
    }
    let s = &path[..len];

    if s == b"curl" || s.ends_with(b"/curl") || s.ends_with(b"curl") {
        return true;
    }

    let mut i = 0;
    while i + 4 <= len {
        if s[i] == b'c' && s[i + 1] == b'u' && s[i + 2] == b'r' && s[i + 3] == b'l' {
            let before_ok = (i == 0) || (s[i - 1] == b'/');
            let after_ok = (i + 4 == len) || (s[i + 4] == b' ') || (s[i + 4] == 0);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }

    false
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
