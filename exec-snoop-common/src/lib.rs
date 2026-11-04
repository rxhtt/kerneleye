#![no_std]

pub const TASK_COMM_LEN: usize = 16;
pub const MAX_ARGS_LEN: usize = 256;
pub const MAX_AGENT_PIDS: u32 = 1024;
pub const PROTECTED_AGENT_PIDS_MAP: &str = "PROTECTED_AGENT_PIDS";

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub args_len: usize,
    pub comm: [u8; TASK_COMM_LEN],
    pub args: [u8; MAX_ARGS_LEN],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessExecEvent {}
