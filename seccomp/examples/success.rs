extern crate seccomp;

use std::io::{self, Write};

use seccomp::{Action, Compare, Filter, get_syscall_number};
use seccomp::Op::*;


fn main() {
    println!("before filtering");
    let mut stderr = io::stderr();

    let mut filt = Filter::new(Action::Kill).expect("could not create filter");

    // Allow writing to stdout.
    let write_syscall = get_syscall_number("write").expect("could not get write() syscall number");
    filt.add_rule(Action::Allow, write_syscall, &[
        Compare::new(0, OpEq, 1),
    ]).expect("could not add rule");

    // Generic syscalls we allow.
    let generic_syscalls = &["sigaltstack", "munmap", "exit_group"];
    for syscall in generic_syscalls.into_iter() {
        let sn = get_syscall_number(syscall).expect("could not get syscall number");
        filt.add_rule(Action::Allow, sn, &[]).expect("could not add rule");
    }

    // Load into the kernel.
    filt.load().expect("could not load filter");

    // This should work.
    println!("after filtering");

    // If you uncomment this, the process will be killed.
    // let _ = stderr.write(b"this will fail\n");
}
