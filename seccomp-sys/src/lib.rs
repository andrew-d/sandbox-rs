#![allow(non_camel_case_types)]

extern crate libc;

use std::mem;
use libc::{c_char, c_int, c_uint, c_void};

// Valid values for seccomp.mode and prctl(PR_SET_SECCOMP, <mode>)
pub const SECCOMP_MODE_DISABLED: u32 = 0; /* seccomp is not in use. */
pub const SECCOMP_MODE_STRICT: u32 = 1; /* uses hard-coded filter. */
pub const SECCOMP_MODE_FILTER: u32 = 2; /* uses user-supplied filter. */

// Valid operations for seccomp syscall.
pub const SECCOMP_SET_MODE_STRICT: u32 = 0;
pub const SECCOMP_SET_MODE_FILTER: u32 = 1;

// Valid flags for SECCOMP_SET_MODE_FILTER
pub const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1;

pub const SECCOMP_RET_KILL: u32 = 0x00000000;  /* kill the task immediately */
pub const SECCOMP_RET_TRAP: u32 = 0x00030000;  /* disallow and force a SIGSYS */
pub const SECCOMP_RET_ERRNO: u32 = 0x00050000; /* returns an errno */
pub const SECCOMP_RET_TRACE: u32 = 0x7ff00000; /* pass to a tracer or disallow */
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff0000; /* allow */

// Masks
pub const SECCOMP_RET_ACTION: u32 = 0x7fff0000;
pub const SECCOMP_RET_DATA: u32 = 0x0000ffff;

pub type scmp_filter_ctx = *mut c_void;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum scmp_filter_attr {
    SCMP_FLTATR_ACT_DEFAULT = 1,
    SCMP_FLTATR_ACT_BADARCH = 2,
    SCMP_FLTATR_CTL_NNP = 3,
    SCMP_FLTATR_CTL_TSYNC = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum scmp_compare {
    SCMP_CMP_NE = 1,
    SCMP_CMP_LT = 2,
    SCMP_CMP_LE = 3,
    SCMP_CMP_EQ = 4,
    SCMP_CMP_GE = 5,
    SCMP_CMP_GT = 6,
    SCMP_CMP_MASKED_EQ = 7,
}

pub type scmp_datum_t = u64;

#[repr(C)]
#[derive(Debug, Copy, PartialEq, Eq, Hash)]
pub struct scmp_arg_cmp {
    pub arg: c_uint,
    pub op: scmp_compare,
    pub datum_a: scmp_datum_t,
    pub datum_b: scmp_datum_t,
}

impl Clone for scmp_arg_cmp {
    fn clone(&self) -> Self {
        *self
    }
}

impl Default for scmp_arg_cmp {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

#[link(name = "seccomp")]
extern "C" {
    pub fn seccomp_init(def_action: u32) -> scmp_filter_ctx;
    pub fn seccomp_reset(ctx: scmp_filter_ctx, def_action: u32) -> c_int;
    pub fn seccomp_release(ctx: scmp_filter_ctx);
    pub fn seccomp_merge(ctx_dst: scmp_filter_ctx, ctx_src: scmp_filter_ctx) -> c_int;
    pub fn seccomp_arch_resolve_name(arch_name: *const c_char) -> u32;
    pub fn seccomp_arch_native() -> u32;
    pub fn seccomp_arch_exist(ctx: scmp_filter_ctx, arch_token: u32) -> c_int;
    pub fn seccomp_arch_add(ctx: scmp_filter_ctx, arch_token: u32) -> c_int;
    pub fn seccomp_arch_remove(ctx: scmp_filter_ctx, arch_token: u32) -> c_int;
    pub fn seccomp_load(ctx: scmp_filter_ctx) -> c_int;
    pub fn seccomp_attr_get(ctx: scmp_filter_ctx,
                            attr: scmp_filter_attr,
                            value: *mut u32)
                            -> c_int;
    pub fn seccomp_attr_set(ctx: scmp_filter_ctx, attr: scmp_filter_attr, value: u32) -> c_int;
    pub fn seccomp_syscall_resolve_num_arch(arch_token: u32, num: c_int) -> *mut c_char;
    pub fn seccomp_syscall_resolve_name_arch(arch_token: u32, name: *const c_char) -> c_int;
    pub fn seccomp_syscall_resolve_name_rewrite(arch_token: u32, name: *const c_char) -> c_int;
    pub fn seccomp_syscall_resolve_name(name: *const c_char) -> c_int;
    pub fn seccomp_syscall_priority(ctx: scmp_filter_ctx, syscall: c_int, priority: u8) -> c_int;
    pub fn seccomp_rule_add(ctx: scmp_filter_ctx,
                            action: u32,
                            syscall: c_int,
                            arg_cnt: c_uint,
                            ...)
                            -> c_int;
    pub fn seccomp_rule_add_array(ctx: scmp_filter_ctx,
                                  action: u32,
                                  syscall: c_int,
                                  arg_cnt: c_uint,
                                  arg_array: *const scmp_arg_cmp)
                                  -> c_int;
    pub fn seccomp_rule_add_exact(ctx: scmp_filter_ctx,
                                  action: u32,
                                  syscall: c_int,
                                  arg_cnt: c_uint,
                                  ...)
                                  -> c_int;
    pub fn seccomp_rule_add_exact_array(ctx: scmp_filter_ctx,
                                        action: u32,
                                        syscall: c_int,
                                        arg_cnt: c_uint,
                                        arg_array: *const scmp_arg_cmp)
                                        -> c_int;
    pub fn seccomp_export_pfc(ctx: scmp_filter_ctx, fd: c_int) -> c_int;
    pub fn seccomp_export_bpf(ctx: scmp_filter_ctx, fd: c_int) -> c_int;
}
