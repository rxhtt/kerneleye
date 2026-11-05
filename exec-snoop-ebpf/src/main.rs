#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{lsm, map, tracepoint},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, TracePointContext},
    EbpfContext,
};
use exec_snoop_common::{
    ConfinementViolationEvent, ProcessExecEvent, MAX_AGENT_PIDS, MAX_ARGS_LEN,
};

mod vmlinux;
use vmlinux::{linux_binprm, sockaddr, task_struct};

macro_rules! bpf_core_read {
    ($target:expr) => {
        aya_ebpf::helpers::bpf_probe_read_kernel(core::ptr::addr_of!($target))
    };
}

#[map]
static RINGBUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static VIOLATIONS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static DROPPED_EVENTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
static PROTECTED_AGENT_PIDS: HashMap<u32, u32> = HashMap::with_max_entries(MAX_AGENT_PIDS, 0);

#[map]
static BLOCKED_BINARIES: HashMap<[u8; 16], u8> = HashMap::with_max_entries(64, 0);

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

    // BTF-confirmed offsets for sched_process_fork on this kernel:
    //   parent_pid: bits_offset=96 -> byte offset 12
    //   child_pid:  bits_offset=160 -> byte offset 20
    let is_parent_fenced = unsafe {
        PROTECTED_AGENT_PIDS.get(&current_tgid).is_some()
            || PROTECTED_AGENT_PIDS.get(&current_pid).is_some()
            || ctx.read_at::<u32>(12).map(|p| PROTECTED_AGENT_PIDS.get(&p).is_some()).unwrap_or(false)
    };

    if is_parent_fenced {
        if let Ok(child) = unsafe { ctx.read_at::<u32>(20) } {
            if child > 0 {
                let _ = PROTECTED_AGENT_PIDS.insert(&child, &1, 0);
            }
        }
    }

    Ok(())
}

unsafe fn get_ppid() -> u32 {
    let task = unsafe { aya_ebpf::helpers::bpf_get_current_task() } as *const task_struct;
    if task.is_null() {
        return 0;
    }

    let parent = match unsafe { bpf_core_read!((*task).real_parent) } {
        Ok(ptr) => ptr,
        Err(_) => return 0,
    };

    if parent.is_null() {
        return 0;
    }

    match unsafe { bpf_core_read!((*parent).tgid) } {
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

#[inline(always)]
fn get_fenced_root_pid(current_tgid: u32, current_pid: u32) -> u32 {
    if unsafe { PROTECTED_AGENT_PIDS.get(&current_tgid).is_some() } {
        return current_tgid;
    }
    if unsafe { PROTECTED_AGENT_PIDS.get(&current_pid).is_some() } {
        return current_pid;
    }

    let mut task = unsafe { aya_ebpf::helpers::bpf_get_current_task() as *const task_struct };
    for _ in 0..4 {
        if task.is_null() {
            break;
        }

        let parent: *mut task_struct = match unsafe { bpf_core_read!((*task).real_parent) } {
            Ok(p) => p,
            Err(_) => break,
        };

        if parent.is_null() || (parent as *const task_struct) == task {
            break;
        }

        let ptgid: u32 = match unsafe { bpf_core_read!((*parent).tgid) } {
            Ok(v) => v,
            Err(_) => break,
        };

        let ppid_val: u32 = match unsafe { bpf_core_read!((*parent).pid) } {
            Ok(v) => v,
            Err(_) => break,
        };

        if ptgid > 0 && unsafe { PROTECTED_AGENT_PIDS.get(&ptgid).is_some() } {
            return ptgid;
        }

        if ppid_val > 0 && unsafe { PROTECTED_AGENT_PIDS.get(&ppid_val).is_some() } {
            return ppid_val;
        }

        task = parent as *const task_struct;
    }

    0
}

#[inline(always)]
fn emit_violation(agent_pid: u32, child_pid: u32, comm: [u8; 16], binary: &[u8]) {
    if let Some(mut entry) = VIOLATIONS.reserve::<ConfinementViolationEvent>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            (*ptr).timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
            (*ptr).agent_pid = agent_pid;
            (*ptr).child_pid = child_pid;
            (*ptr).comm = comm;
            let mut bin = [0u8; 32];
            let n = if binary.len() < 32 { binary.len() } else { 31 };
            for i in 0..31 {
                if i < n {
                    bin[i] = binary[i];
                }
            }
            (*ptr).binary = bin;
        }
        entry.submit(0);
    }
}

#[inline(always)]
fn extract_basename_key(path: &[u8]) -> [u8; 16] {
    let mut len = path.len();
    if len > 0 && path[len - 1] == 0 {
        len -= 1;
    }
    let mut start = 0usize;
    let bound = if len < 64 { len } else { 64 };
    for i in 0..64 {
        if i < bound && path[i] == b'/' {
            start = i + 1;
        }
    }
    let mut key = [0u8; 16];
    if start <= len {
        let name_len = len - start;
        for j in 0..15 {
            if j < name_len && start + j < path.len() {
                key[j] = path[start + j];
            }
        }
    }
    key
}

#[inline(always)]
fn is_blocked_binary(path: &[u8]) -> bool {
    let key = extract_basename_key(path);
    if unsafe { BLOCKED_BINARIES.get(&key).is_some() } {
        return true;
    }
    // Backward-compatibility fallback: check "curl"
    if key[0] == b'c' && key[1] == b'u' && key[2] == b'r' && key[3] == b'l' && key[4] == 0 {
        return true;
    }
    false
}

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    let bprm: *const linux_binprm = ctx.arg(0);
    if bprm.is_null() {
        return 0;
    }

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let current_tgid = (pid_tgid >> 32) as u32;
    let current_pid = pid_tgid as u32;

    let fenced_root_pid = get_fenced_root_pid(current_tgid, current_pid);
    if fenced_root_pid == 0 {
        return 0;
    }

    // Auto-propagate fenced state to current process
    let _ = PROTECTED_AGENT_PIDS.insert(&current_tgid, &1, 0);
    let _ = PROTECTED_AGENT_PIDS.insert(&current_pid, &1, 0);

    // Fast-path: check comm
    if let Ok(comm) = aya_ebpf::helpers::bpf_get_current_comm() {
        if unsafe { BLOCKED_BINARIES.get(&comm).is_some() }
            || (comm[0] == b'c' && comm[1] == b'u' && comm[2] == b'r' && comm[3] == b'l')
        {
            emit_violation(fenced_root_pid, current_pid, comm, b"curl\0");
            return -1; // -EPERM
        }
    }

    // Read bprm->filename via CO-RE field accessor
    let mut buf = [0u8; 64];
    if let Ok(filename_ptr) = unsafe { bpf_core_read!((*bprm).filename) } {
        if !filename_ptr.is_null() {
            if let Ok(bytes) = unsafe {
                aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes(filename_ptr, &mut buf)
            } {
                if is_blocked_binary(bytes) {
                    let comm = aya_ebpf::helpers::bpf_get_current_comm().unwrap_or([0u8; 16]);
                    emit_violation(fenced_root_pid, current_pid, comm, bytes);
                    return -1; // -EPERM
                }
            } else if let Ok(bytes) = unsafe {
                aya_ebpf::helpers::bpf_probe_read_user_str_bytes(filename_ptr, &mut buf)
            } {
                if is_blocked_binary(bytes) {
                    let comm = aya_ebpf::helpers::bpf_get_current_comm().unwrap_or([0u8; 16]);
                    emit_violation(fenced_root_pid, current_pid, comm, bytes);
                    return -1; // -EPERM
                }
            }
        }
    }

    0
}

#[lsm(hook = "socket_connect")]
pub fn socket_connect(ctx: LsmContext) -> i32 {
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let current_tgid = (pid_tgid >> 32) as u32;
    let current_pid = pid_tgid as u32;

    let fenced_root_pid = get_fenced_root_pid(current_tgid, current_pid);
    if fenced_root_pid == 0 {
        return 0;
    }

    // Auto-propagate fenced state
    let _ = PROTECTED_AGENT_PIDS.insert(&current_tgid, &1, 0);
    let _ = PROTECTED_AGENT_PIDS.insert(&current_pid, &1, 0);

    // Check address family via CO-RE field accessor (arg 1)
    let addr: *const sockaddr = ctx.arg(1);
    if !addr.is_null() {
        if let Ok(family) = unsafe { bpf_core_read!((*addr).sa_family) } {
            // AF_INET = 2, AF_INET6 = 10
            if family == 2 || family == 10 {
                let comm = aya_ebpf::helpers::bpf_get_current_comm().unwrap_or([0u8; 16]);
                emit_violation(fenced_root_pid, current_pid, comm, b"network:socket_connect\0");
                return -1; // -EPERM
            }
        }
    }

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
