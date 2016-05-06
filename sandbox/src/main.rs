extern crate clap;
#[macro_use] extern crate lazy_static;
extern crate libc;
extern crate nix;
extern crate seccomp;

use std::ffi::CString;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::mem;
use std::path::Path;
use std::process::exit;
use std::ptr;

use clap::{Arg, App};
use libc::{c_int, c_void};
use nix::errno::errno;
use nix::sys::{epoll, signal, wait};
use seccomp::{Action, Compare, Filter, Op, get_syscall_number};


lazy_static! {
    static ref EXECVE_SYSCALL: i32 = {
        get_syscall_number("execve").expect("could not get execve syscall")
    };

    static ref CLONE_SYSCALL: i32 = {
        get_syscall_number("clone").expect("could not get clone syscall")
    };
}


macro_rules! eprintln {
    ($($arg:tt)*) => { {
        let r = writeln!(&mut ::std::io::stderr(), $($arg)*);
        r.expect("failed printing to stderr");
    } }
}


macro_rules! ptry {
    ($ex:expr, $fmt:expr, $($arg:tt)*) => (
        match $ex {
            -1 => {
                eprintln!($fmt, $($arg)*);
                exit(1);
            },
            x => x,
        }
    );

    ($ex:expr, $fmt:expr) => (
        ptry!($ex, $fmt,)
    );

    ($ex:expr) => (
        ptry!($ex, "an error occured")
    );
}


macro_rules! ftry {
    ($ex:expr, $fmt:expr, $($arg:tt)*) => (
        match $ex {
            Err(e) => {
                let msg = format!($fmt, $($arg)*);
                eprintln!("{}: {:?}", msg, e);
                exit(1);
            }
            Ok(v) => v,
        }
    );

    ($ex:expr, $fmt:expr) => (
        ftry!($ex, $fmt,)
    );

    ($ex:expr) => (
        ftry!($ex, "an error occured")
    );
}


// From #include <linux/prctl.h>
pub const PR_SET_PDEATHSIG: c_int = 1;

// From #include <unistd.h> on modern Linux
extern {
    fn execvpe(file: *const libc::c_char, argv: *const *const libc::c_char,
               envp: *const *const libc::c_char) -> c_int;
}


fn main() {
    let matches = App::new("sandbox")
                      .version("0.0.1")
                      .author("Andrew Dunham <andrew@du.nham.ca>")
                      .arg(Arg::with_name("user")
                           .short("u")
                           .long("user")
                           .value_name("USER")
                           .help("The user to run the program as")
                           .takes_value(true))
                      .arg(Arg::with_name("hostname")
                           .short("n")
                           .long("hostname")
                           .value_name("NAME")
                           .help("The hostname to set the container to")
                           .takes_value(true))
                      .arg(Arg::with_name("syscalls-file")
                           .short("S")
                           .long("syscalls-file")
                           .value_name("FILE")
                           .help("Whitelist file containing one syscall name per line")
                           .takes_value(true))
                      .arg(Arg::with_name("chroot")
                           .help("chroot to run the command in")
                           .index(1))
                      .arg(Arg::with_name("command")
                           .help("Command to run")
                           .index(2)
                           .multiple(true))
                      .get_matches();

    let chroot = match matches.value_of("chroot") {
        Some(v) => v,
        None => {
            eprintln!("no chroot path given");
            exit(1);
        },
    };
    let pchroot = Path::new(chroot);
    let cchroot = CString::new(chroot).expect("could not make path for chroot");

    let command = match matches.values_of("command") {
        Some(v) => v.collect::<Vec<_>>(),
        None => {
            eprintln!("no command given");
            exit(1);
        },
    };
    let ccommand = {
        let mut res = vec![];
        for arg in command.iter() {
            res.push(CString::new(*arg).expect("invalid argument"));
        }

        res
    };

    // TODO: trace in learning mode
    let mut filter = ftry!(Filter::new(Action::Kill), "could not create seccomp filter");

    // If we have a whitelist, open it.
    if let Some(whitelist_file) = matches.value_of("syscalls-file") {
        ftry!(parse_whitelist_file(&mut filter, whitelist_file),
            "could not parse whitelist file");
    }

    // Always permit the 'execve' syscall, since it's necessary for us to run the child process.
    ftry!(filter.add_rule(Action::Allow, *EXECVE_SYSCALL, &[]));

    // TODO: parse syscalls from flag

    let epoll_fd = ftry!(epoll::epoll_create(), "could not create epoll");

    let mut mask = signal::SigSet::empty();
    ftry!(mask.add(signal::SIGCHLD));
    ftry!(mask.add(signal::SIGHUP));
    ftry!(mask.add(signal::SIGINT));
    ftry!(mask.add(signal::SIGTERM));

    let mut old_mask = signal::SigSet::empty();
    ftry!(signal::pthread_sigmask(signal::SIG_BLOCK, Some(&mask), Some(&mut old_mask)));

    let sig_fd = ptry!(unsafe { libc::signalfd(-1, mask.as_ref(), libc::SFD_CLOEXEC) });
    epoll_add(epoll_fd, sig_fd, epoll::EPOLLIN);

    let pipe_in: &mut [c_int] = &mut [0, 0];
    let pipe_out: &mut [c_int] = &mut [0, 0];
    let pipe_err: &mut [c_int] = &mut [0, 0];

    ptry!(unsafe { libc::pipe(pipe_in.as_mut_ptr()) });
    ptry!(unsafe { libc::pipe(pipe_out.as_mut_ptr()) });
    set_non_blocking(pipe_out[0]);
    ptry!(unsafe { libc::pipe(pipe_err.as_mut_ptr()) });
    set_non_blocking(pipe_err[0]);

    // TODO: add stdin to epoll

    epoll_add(epoll_fd, pipe_out[0], epoll::EPOLLIN);
    epoll_add(epoll_fd, pipe_err[0], epoll::EPOLLIN);
    epoll_add(epoll_fd, pipe_in[1], epoll::EPOLLET | epoll::EPOLLOUT);

    let flags = libc::SIGCHLD | libc::CLONE_NEWIPC | libc::CLONE_NEWNS |
        libc::CLONE_NEWPID | libc::CLONE_NEWUTS | libc::CLONE_NEWNET;

    let pid = ptry!(unsafe { libc::syscall(*CLONE_SYSCALL as i64, flags, ptr::null::<*const c_void>()) }) as libc::pid_t;

    if pid == 0 {
        unsafe {
            libc::dup2(pipe_in[0], libc::STDIN_FILENO);
            libc::close(pipe_in[0]);
            libc::close(pipe_in[1]);

            libc::dup2(pipe_out[0], libc::STDOUT_FILENO);
            libc::close(pipe_out[0]);
            libc::close(pipe_out[1]);

            libc::dup2(pipe_err[0], libc::STDERR_FILENO);
            libc::close(pipe_err[0]);
            libc::close(pipe_err[1]);

            // Kill this process if the parent dies.
            ptry!(libc::prctl(PR_SET_PDEATHSIG, libc::SIGKILL));

            // Set the host name.
            let hostname = matches.value_of("hostname").unwrap_or("sandbox");
            let hostname = CString::new(hostname).unwrap_or_else(|_| CString::new("sandbox").unwrap());
            let hostname = hostname.to_bytes_with_nul();
            ptry!(libc::sethostname(hostname.as_ptr() as *const libc::c_char, hostname.len() - 1));

            let dot = CString::new(".").unwrap();
            let slash = CString::new("/").unwrap();
            let bind = CString::new("bind").unwrap();
            let tmpfs = CString::new("tmpfs").unwrap();

            // Avoid propagating mounts to or from the parent's mount namespace.
            ptry!(libc::mount(
                ptr::null(),
                slash.as_ptr(),
                ptr::null(),
                libc::MS_PRIVATE | libc::MS_REC,
                ptr::null()
            ));

            // Turn the directory into a bind mount
            ptry!(libc::mount(
                cchroot.as_ptr(),
                cchroot.as_ptr(),
                bind.as_ptr(),
                libc::MS_BIND | libc::MS_REC,
                ptr::null()
            ));

            // Re-mount as read-only
            ptry!(libc::mount(
                cchroot.as_ptr(),
                cchroot.as_ptr(),
                bind.as_ptr(),
                libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_REC,
                ptr::null()
            ));

            // TODO: mount proc/dev/(dev/shm)

            // Try to mount /tmp
            // Note: if we get here, we can already create a CString from our chroot, since we
            // tried above, so we can use .unwrap() for that bit.
            let x = pchroot.join("tmp");
            let tmp_path = CString::new(x.to_str().unwrap()).unwrap();

            let res = libc::mount(
                ptr::null(),
                tmp_path.as_ptr(),
                tmpfs.as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV,
                ptr::null()
            );
            if res == -1 && errno() != libc::ENOENT {
                eprintln!("mounting /tmp failed");
                exit(1);
            }

            // TODO: custom bind mounts

            // Preserve a reference to the target directory
            ptry!(libc::chdir(cchroot.as_ptr()));

            // Make the working directory into the root of the mount namespace.
            ptry!(libc::mount(
                dot.as_ptr(),
                slash.as_ptr(),
                ptr::null(),
                libc::MS_MOVE,
                ptr::null()
            ));

            // Chroot into the root of the mount namespace
            ptry!(libc::chroot(dot.as_ptr()), "chroot into `{}` failed", chroot);
            ptry!(libc::chdir(slash.as_ptr()), "entering chroot `{}` failed", chroot);

            // TODO: set username
            // TODO: mount home directory for the user as a tmpfs
            // TODO: chdir into the home directory for that user

            // Create a new session
            ptry!(libc::setsid());

            // TODO: initgroups, setresgid, setresuid

            // Restore our previous signal mask
            ftry!(signal::pthread_sigmask(signal::SIG_BLOCK, Some(&old_mask), None));

            let env = vec![
                b"PATH=/usr/local/bin:/usr/bin:/bin".as_ptr() as *const libc::c_char,
                b"HOME=TODO".as_ptr() as *const libc::c_char,
                b"USER=TODO".as_ptr() as *const libc::c_char,
                b"LOGNAME=TODO".as_ptr() as *const libc::c_char,
            ];
            let ptrs = ccommand.iter().map(|v| v.as_ptr()).collect::<Vec<_>>();

            // Load the seccomp filter now that we're almost done
            ftry!(filter.load());

            // Finally, exec the new process.
            ptry!(execvpe(
                ccommand[0].as_ptr(),
                (&*ptrs).as_ptr(),
                (&*env).as_ptr()
            ));
        }
    }

    println!("in the parent");

    // Don't need this any more, since the child uses it.
    drop(filter);

    // TODO: timeout through timerfd

    let stdin_buf: &[u8] = &[0; 512];
    let stdin_bytes_read = 0usize;

    loop {
        let mut events: [epoll::EpollEvent; 8];
        unsafe {
            events = mem::zeroed();
        }

        let num_events = match epoll::epoll_wait(epoll_fd, &mut events, -1) {
            Ok(n) => n,
            Err(nix::Error::Sys(nix::Errno::EINTR)) => continue,
            Err(e) => {
                eprintln!("error in epoll(): {}", e);
                exit(1);
            },
        };

        for i in 0..num_events {
            let event = events[i];

            if event.events.contains(epoll::EPOLLERR) {
                unsafe { libc::close(event.data as c_int) };
                continue;
            }

            // Have input from the child process
            if event.events.contains(epoll::EPOLLIN) {
                if false /* TODO: timeouts */ {
                } else if event.data as c_int == sig_fd {
                    handle_signal(pid, sig_fd);
                } else if event.data as c_int == pipe_out[0] {
                    copy_to_stdstream(pipe_out[0], /* STDOUT_FILENO */ 1);
                } else if event.data as c_int == pipe_err[0] {
                    copy_to_stdstream(pipe_err[0], /* STDERR_FILENO */ 2);
                } else if event.data as c_int == 0 /* STDIN_FILENO */ {
                    // TODO
                }
            }

            // Child process is ready for more input
            if event.events.contains(epoll::EPOLLOUT) && event.data as c_int == pipe_in[1] {
                // TODO
            }

            if event.events.contains(epoll::EPOLLHUP) {
                // If stdin is closed, then we remove it from the epoll.
                if event.data as c_int == /* STDIN_FILENO */ 0 {
                    unsafe {
                        // Also close the write end of the pipe to our child.
                        libc::close(pipe_in[1]);

                        let dummy: epoll::EpollEvent = mem::zeroed();
                        ftry!(epoll::epoll_ctl(
                            epoll_fd,
                            epoll::EpollOp::EpollCtlDel,
                            0 /* STDIN_FILENO */,
                            &dummy
                        ));
                    }
                }

                // Close this FD either way
                unsafe { libc::close(event.data as c_int) };
            }
        }
    }
}

fn handle_signal(pid: libc::pid_t, sig_fd: c_int) {
    let info: libc::signalfd_siginfo = unsafe { mem::zeroed() };

    let res = ptry!(unsafe { libc::read(
        sig_fd,
        mem::transmute(&info),
        mem::size_of_val(&info)
    )});

    if (res as usize) != mem::size_of_val(&info) {
        eprintln!("read the wrong number of bytes");
        exit(1);
    }

    match info.ssi_signo as c_int {
        libc::SIGHUP | libc::SIGINT | libc::SIGTERM => {
            eprintln!("interrupted, stopping early");
            exit(1);
        },
        libc::SIGCHLD => { /* Expected */ },
        other => {
            eprintln!("got an unexpected signal: {}", other);
            exit(1);
        },
    };

    loop {
        let options = libc::WNOHANG | /* __WALL */ 0x40000000;
        let mut status: c_int = 0;
        let res = ptry!(unsafe {
            libc::waitpid(-1, &mut status as *mut i32, options)
        }, "could not waitpid()");
        if res == 0 {
            break;
        }

        if (status & 0xFF) == 0x7F {
            // Stopped
            // TODO
        } else if ((((status & 0x7f) + 1) as i8) >> 1) > 0 {
            // Signalled
            eprintln!("application terminated abnormally with signal {}", status & 0x7F);
            exit(1);
        } else if (status & 0x7F) == 0 && res == pid {
            exit(status as c_int);
        }
    }
}

fn parse_whitelist_file(filter: &mut Filter, path: &str) -> io::Result<()> {
    let f = try!(File::open(path));
    let reader = BufReader::new(f);

    for line in reader.lines() {
        let line = try!(line);
        let parts: Vec<&str> = line.splitn(2, ':').collect();

        let name = parts[0].trim();
        let syscall_num = match get_syscall_number(name) {
            Some(n) => n,
            None => {
                let _ = eprintln!("unknown syscall '{}'", name);
                continue;
            },
        };

        let mut conditions = vec![];
        if parts.len() == 2 {
            let cond_parts = parts[1].split(',').collect::<Vec<_>>();

            for part in cond_parts.iter() {
                let args = part.trim().split(' ').collect::<Vec<_>>();
                if args.len() != 3 {
                    let _ = eprintln!("condition does not have three clauses: {}", part);
                    continue;
                }

                let real_op = match args[1] {
                    "==" => Op::OpEq,
                    "!=" => Op::OpNe,
                    ">"  => Op::OpGt,
                    "<"  => Op::OpLt,
                    ">=" => Op::OpGe,
                    "<=" => Op::OpLe,
                    x => {
                        eprintln!("unknown operation: {}", x);
                        continue;
                    }
                };

                let arg = match u32::from_str_radix(args[0], 10) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("bad argument index '{}': {}", args[0], e);
                        continue;
                    },
                };

                let value = match u64::from_str_radix(args[2], 10) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("bad value '{}': {}", args[2], e);
                        continue;
                    },
                };

                conditions.push(Compare::new(arg, real_op, value));
            }

        }

        try!(filter.add_rule(Action::Allow, syscall_num, &*conditions));
    }

    Ok(())
}

fn epoll_add(epoll_fd: c_int, fd: c_int, events: epoll::EpollEventKind) {
    let event = epoll::EpollEvent {
        events: events,
        data: fd as u64,
    };

    ftry!(epoll::epoll_ctl(epoll_fd, epoll::EpollOp::EpollCtlAdd, fd, &event), "epoll_add failed");
}

fn set_non_blocking(fd: c_int) {
    let flags = ptry!(unsafe { libc::fcntl(fd, libc::F_GETFL, 0) });
    ptry!(unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) });
}

fn copy_to_stdstream(in_fd: c_int, out_fd: c_int) {
    let mut buffer: [u8; 8192];
    unsafe { buffer = mem::uninitialized(); }

    let res = unsafe { libc::read(in_fd, buffer.as_mut_ptr() as *mut c_void, buffer.len()) };
    if res == -1 {
        if errno() != libc::EAGAIN {
            eprintln!("error copying data");
            exit(1);
        }

        return;
    }

    ptry!(unsafe { libc::write(out_fd, buffer.as_ptr() as *const c_void, res as usize) });
}
