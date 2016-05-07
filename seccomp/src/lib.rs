extern crate libc;
extern crate seccomp_sys as ffi;

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::unix::io::IntoRawFd;

use libc::close;


/// A compare operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    /// Not equal
    OpNe,

    /// Less than
    OpLt,

    /// Less than or equal to
    OpLe,

    /// Equal
    OpEq,

    /// Greater than or equal to
    OpGe,

    /// Greater than
    OpGt,
}

impl Op {
    fn to_c_enum(&self) -> ffi::scmp_compare {
        use Op::*;

        match *self {
            OpNe => ffi::scmp_compare::SCMP_CMP_NE,
            OpLt => ffi::scmp_compare::SCMP_CMP_LT,
            OpLe => ffi::scmp_compare::SCMP_CMP_LE,
            OpEq => ffi::scmp_compare::SCMP_CMP_EQ,
            OpGe => ffi::scmp_compare::SCMP_CMP_GE,
            OpGt => ffi::scmp_compare::SCMP_CMP_GT,
        }
    }
}

/// Compare represents a single comparison operation.
#[derive(Debug)]
pub struct Compare(ffi::scmp_arg_cmp);

impl Compare {
    pub fn new(arg: u32, op: Op, x: u64) -> Compare {
        Compare(ffi::scmp_arg_cmp {
            arg: arg,
            op: op.to_c_enum(),
            datum_a: x,
            datum_b: 0,
        })
    }

    pub fn new_masked_eq(arg: u32, mask: u64, x: u64) -> Compare {
        Compare(ffi::scmp_arg_cmp {
            arg: arg,
            op: ffi::scmp_compare::SCMP_CMP_MASKED_EQ,
            datum_a: mask,
            datum_b: x,
        })
    }
}

/// An action to perform when a `seccomp` ruleset is violated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Kill the process.
    Kill,

    /// Throw a `SIGSYS` signal.
    Trap,

    /// Allow the system call to be executed.
    Allow,

    /// Notify a tracing process with the specified value.
    Trace(u16),

    /// Return the specified error code.
    Errno(u16),
}

impl Action {
    fn to_c_repr(&self) -> u32 {
        use Action::*;

        match *self {
            Kill => ffi::SECCOMP_RET_KILL,
            Trap => ffi::SECCOMP_RET_TRAP,
            Allow => ffi::SECCOMP_RET_ALLOW,
            Trace(val) => {
                ffi::SECCOMP_RET_TRACE | ((val as u32) & ffi::SECCOMP_RET_DATA)
            },
            Errno(err) => {
                ffi::SECCOMP_RET_ERRNO | ((err as u32) & ffi::SECCOMP_RET_DATA)
            },
        }
    }
}

/// Filter represents a filter context in `seccomp`.
///
/// A filter context is intially empty.  Rules can be added to it, after which it can be loaded
/// into the kernel.
#[derive(Debug)]
pub struct Filter {
    ctx: ffi::scmp_filter_ctx,
}

impl Filter {
    /// Creates a new filter context.
    pub fn new(default_action: Action) -> Result<Filter, io::Error> {
        let p = unsafe { ffi::seccomp_init(default_action.to_c_repr()) };

        if p.is_null() {
            return Err(io::Error::last_os_error());
        }

        Ok(Filter{
            ctx: p,
        })
    }

    /// Reset the current filter context, removing all its existing state.
    pub fn reset(&mut self, default_action: Action) -> Result<(), io::Error> {
        let res = unsafe { ffi::seccomp_reset(self.ctx, default_action.to_c_repr()) };

        if res != 0 {
            return Err(io::Error::from_raw_os_error(-res));
        }

        Ok(())
    }

    /// Load the current filter context into the kernel.
    pub fn load(&mut self) -> Result<(), io::Error> {
        let res = unsafe { ffi::seccomp_load(self.ctx) };

        if res != 0 {
            return Err(io::Error::from_raw_os_error(-res));
        }

        Ok(())
    }

    /// Add the given rule to the current filter context.
    pub fn add_rule(&mut self, action: Action, syscall: i32, args: &[Compare]) -> Result<(), io::Error> {
        // Somewhat of a no-op, but...
        let cargs = args.iter().map(|x| {
            let Compare(cv) = *x;
            cv
        }).collect::<Vec<_>>();

        let res = unsafe { ffi::seccomp_rule_add_array(
            self.ctx,
            action.to_c_repr(),
            syscall,
            cargs.len() as u32,
            cargs.as_ptr()
        )};

        if res != 0 {
            return Err(io::Error::from_raw_os_error(-res));
        }

        Ok(())
    }

    /// Export the current filter context - in PFC-formatted, human-readable form - to the given
    /// file.
    pub fn export_pfc(&mut self, dest: File) -> Result<(), io::Error> {
        let fd = dest.into_raw_fd();

        let res = unsafe { ffi::seccomp_export_pfc(self.ctx, fd) };
        unsafe { close(fd) };

        if res != 0 {
            return Err(io::Error::from_raw_os_error(-res));
        }

        Ok(())
    }

    /// Export the current filter context - in Berkeley Packet Filter-formatted, kernel-readable
    /// form - to the given file.
    pub fn export_bpf(&mut self, dest: File) -> Result<(), io::Error> {
        let fd = dest.into_raw_fd();

        let res = unsafe { ffi::seccomp_export_bpf(self.ctx, fd) };
        unsafe { close(fd) };

        if res != 0 {
            return Err(io::Error::from_raw_os_error(-res));
        }

        Ok(())
    }
}

impl Drop for Filter {
    fn drop(&mut self) {
        unsafe { ffi::seccomp_release(self.ctx) };
    }
}

/// Get the syscall number for a given name.
pub fn get_syscall_number(name: &str) -> Option<i32> {
    let cs = match CString::new(name) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let r = unsafe { ffi::seccomp_syscall_resolve_name(cs.as_ptr()) };

    if r == -1 {
        None
    } else {
        Some(r)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_syscall_number() {
        let sn = get_syscall_number("open");
        assert_eq!(sn, Some(2));
    }
}
