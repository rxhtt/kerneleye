#![allow(non_upper_case_globals, non_snake_case, non_camel_case_types, dead_code)]

#[repr(C)]
pub struct task_struct {
    pub _pad0: [u8; 2800],
    pub pid: u32,
    pub tgid: u32,
    pub _pad1: [u8; 8],
    pub real_parent: *mut task_struct,
}

#[repr(C)]
pub struct linux_binprm {
    pub _pad0: [u8; 96],
    pub filename: *const u8,
    pub interp: *const u8,
    pub fdpath: *const u8,
    pub _pad1: [u8; 296],
}

#[repr(C)]
pub struct sockaddr {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}

#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: [u8; 4],
    pub __pad: [u8; 8],
}

#[repr(C)]
pub struct sockaddr_in6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u8; 16],
    pub sin6_scope_id: u32,
}
