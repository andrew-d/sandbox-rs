#![allow(unused_unsafe)]

#[macro_use] extern crate lazy_static;
extern crate libc;
extern crate nix;
extern crate seccomp;

use std::ffi::{self, CStr, CString};
use std::fmt;
use std::io;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::ptr;

use libc::{c_void};
use nix::errno::errno;
use nix::mount;
use nix::sys::{epoll, signal};
use nix::unistd::{chdir, chroot, close, dup2, sethostname, write};

use seccomp::{Action, Compare, Filter, get_syscall_number};


mod ffiext;


lazy_static! {
    static ref EXECVE_SYSCALL: i32 = {
        get_syscall_number("execve").expect("could not get execve syscall")
    };

    static ref CLONE_SYSCALL: i32 = {
        get_syscall_number("clone").expect("could not get clone syscall")
    };
}


// Wrapper around a standard POSIX function that returns -1 on error.
macro_rules! ptry {
    ($syscall:ident, $ex:expr) => {
        match unsafe { $ex } {
            -1 => {
                return Err(Error::PosixError(stringify!($syscall), errno()));
            },
            x => x,
        }
    };
}


// Simple wrapper that prints an error to standard out and then exits the process.
macro_rules! etry {
    ($ex:expr) => {
        match $ex {
            Ok(..) => {},
            Err(e) => {
                let msg = format!("{:?}", e);
                let _ = write(
                    libc::STDERR_FILENO,
                    msg.as_ref()
                );

                unsafe { libc::exit(1) };
            },
        }
    };

    ($syscall:ident, $ex:expr) => {
        match $ex {
            -1 => {
                let msg = format!("PosixError({}, {})", stringify!($syscall), errno());
                let _ = write(
                    libc::STDERR_FILENO,
                    msg.as_ref()
                );

                unsafe { libc::exit(1) };
            },
            x => x,
        }
    };
}


/// Action to perform on a blacklist failure.
pub enum DefaultAction {
    /// Kill the sandboxed process on a blacklist failure (the default).
    Kill,

    /// Permit the sandboxed syscall.  This is generally a bad idea - whitelisting syscalls
    /// directly instead of blacklisting potentially-bad ones is more secure.
    Permit,

    /// Call a callback to determine if the syscall is allowed to execute.  This could also be
    /// useful for a "learning mode" or something similar.
    Callback(Box<FnMut(&str, &[i64]) -> DefaultActionResult>),
}


impl fmt::Debug for DefaultAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        use DefaultAction::*;

        match *self {
            Kill        => write!(f, "Kill"),
            Permit      => write!(f, "Permit"),
            Callback(_) => write!(f, "Callback"),
        }
    }
}


#[derive(Debug, Clone, Copy)]
pub enum DefaultActionResult {
    Permit,
    Deny,
}


/// A whitelist entry for a single syscall.
#[derive(Debug)]
pub struct WhitelistEntry {
    pub name: String,
    pub action: Action,
    pub args: Option<Vec<Compare>>,
}


/// The configuration for a sandboxed process.
#[derive(Debug)]
pub struct Config<'a> {
    /// The `chroot` to run in.
    pub chroot: &'a Path,

    /// The default action to perform when a blacklisted syscall is called.
    pub default_action: DefaultAction,

    /// Any syscalls to whitelist.
    pub whitelist: Vec<WhitelistEntry>,

    /// The hostname to set.  If not given, will default to "sandbox".
    pub hostname: Option<String>,

    /// The username to change to.  If not given, will default to "nobody".
    pub username: Option<String>,

    /// If `true`, mount `/proc` in the container (default: false).
    pub mount_proc: bool,

    /// If `true`, mount `/dev` in the container as devtmpfs (default: false).
    pub mount_dev: bool,
}


impl<'a> Config<'a> {
    pub fn default_with(chroot: &Path) -> Config {
        Config {
            chroot: chroot,
            default_action: DefaultAction::Kill,
            whitelist: vec![],
            hostname: None,
            username: None,
            mount_proc: false,
            mount_dev: false,
        }
    }
}


/// Error type for `sandbox-rs`.
#[derive(Debug)]
pub enum Error {
    /// A string had an unexpected null byte in it.
    NulError,

    /// An I/O error occurred.
    IoError(io::Error),

    /// The given syscall name does not exist.
    NoSuchSyscall(String),

    /// An error occured when using Nix.
    NixError(nix::Error),

    /// A generic POSIX error occurred.  The parameters are the syscall name and the value of
    /// `errno`.
    PosixError(&'static str, i32),

    /// Another error occurred.
    Other(&'static str),
}

impl From<ffi::NulError> for Error {
    fn from(_: ffi::NulError) -> Error {
        Error::NulError
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::IoError(e)
    }
}

impl From<nix::Error> for Error {
    fn from(e: nix::Error) -> Error {
        Error::NixError(e)
    }
}

/// Manager for a sandbox.  Given a config, allows spawning a process in the sandbox and managing
/// it.
#[derive(Debug)]
pub struct Manager<'a> {
    // Input config
    config: Config<'a>,

    // Various C strings that we convert up front.
    chroot: CString,
    username: CString,

    // Seccomp filter
    filter: Filter,

    // Various file descriptors.
    epoll: RawFd,
    sigfd: RawFd,

    // Pipes for stdin/stdout/stderr
    pipe_in:  [RawFd; 2],
    pipe_out: [RawFd; 2],
    pipe_err: [RawFd; 2],
}

impl<'a> Manager<'a> {
    pub fn new(conf: Config) -> Result<Manager, Error> {
        let chroot = match conf.chroot.as_os_str().to_str() {
            Some(s) => s,
            None => return Err(Error::NulError),
        };

        let username = {
            let val = match conf.username {
                Some(ref v) => v,
                None => "nobody",
            };

            try!(CString::new(val))
        };

        let mut filter = try!(Filter::new(match conf.default_action {
            DefaultAction::Kill => Action::Kill,
            DefaultAction::Permit => Action::Allow,
            DefaultAction::Callback(_) => Action::Trace(0),
        }));

        // Add any whitelist entries, if they exist.
        for entry in conf.whitelist.iter() {
            let syscall = match get_syscall_number(&*entry.name) {
                Some(s) => s,
                None => return Err(Error::NoSuchSyscall(entry.name.clone())),
            };

            if let Some(ref args) = entry.args {
                try!(filter.add_rule(entry.action, syscall, &*args));
            } else {
                try!(filter.add_rule(entry.action, syscall, &[]));
            }
        }

        // Need to allow execve to actually run the program.
        try!(filter.add_rule(Action::Allow, *EXECVE_SYSCALL, &[]));

        // Create a epoll FD.
        let epoll = try!(epoll::epoll_create());

        Ok(Manager {
            config: conf,
            chroot: try!(CString::new(chroot)),
            username: username,
            filter: filter,
            epoll: epoll,
            sigfd: epoll,   // TODO: this is not right

            pipe_in:  [0; 2],
            pipe_out: [0; 2],
            pipe_err: [0; 2],
        })
    }

    /// Run a given program in our sandbox.  Note that when function returns, the program is likely
    /// in an inconsistent state, and the only safe avenue is to display the error (if any) and
    /// then immediately exit.
    pub fn launch(&mut self, command: Vec<String>) -> Result<(), Error> {
        // Convert command to a CString array.
        let command = {
            let mut res = vec![];
            for arg in command.into_iter() {
                res.push(try!(CString::new(arg)));
            }

            res
        };

        // Flags for our call to clone()
        let flags = libc::SIGCHLD | libc::CLONE_NEWIPC | libc::CLONE_NEWNS |
            libc::CLONE_NEWPID | libc::CLONE_NEWUTS | libc::CLONE_NEWNET;

        // Actually call clone()
        let pid = ptry!(clone, libc::syscall(
            *CLONE_SYSCALL as i64,
            flags,
            ptr::null::<*const c_void>()
        )) as libc::pid_t;

        if pid == 0 {
            self.run_child(command)
        } else {
            self.run_parent(pid)
        }
    }

    // Note: any failure in the child should result in us terminating the process so the parent can
    // pick up on the error.
    fn run_child(&mut self, command: Vec<CString>) -> ! {
        self.child_set_fds();

        // Kill this process if the parent dies.
        unsafe {
            etry!(prctl, libc::prctl(ffiext::PR_SET_PDEATHSIG, libc::SIGKILL));
        }

        // Miscellaneous hardening things here.
        etry!(self.child_set_hostname());
        etry!(self.child_set_mounts());
        etry!(self.child_do_chroot());
        etry!(self.child_handle_username());

        // TODO: reset process mask

        let prog = command[0].clone();
        let env = vec![
            b"PATH=/usr/local/bin:/usr/bin:/bin".as_ptr() as *const libc::c_char,
            b"HOME=TODO".as_ptr() as *const libc::c_char,
            b"USER=TODO".as_ptr() as *const libc::c_char,
            b"LOGNAME=TODO".as_ptr() as *const libc::c_char,
        ];
        let ptrs = command.into_iter().map(|v| v.as_ptr()).collect::<Vec<_>>();

        // Load the seccomp filter now that we're almost done
        etry!(self.filter.load());

        // Finally, exec the new process.
        unsafe {
            ffiext::execvpe(
                prog.as_ptr(),
                (&*ptrs).as_ptr(),
                (&*env).as_ptr()
            );

            // If we get here, it's an error
            libc::exit(errno());
        }
    }

    // Replace stdin/stdout/stderr with our previously-opened file descriptors.
    fn child_set_fds(&mut self) {
        let _ = dup2(self.pipe_in[0], libc::STDIN_FILENO);
        let _ = close(self.pipe_in[0]);
        let _ = close(self.pipe_in[1]);

        let _ = dup2(self.pipe_out[0], libc::STDOUT_FILENO);
        let _ = close(self.pipe_out[0]);
        let _ = close(self.pipe_out[1]);

        let _ = dup2(self.pipe_err[0], libc::STDERR_FILENO);
        let _ = close(self.pipe_err[0]);
        let _ = close(self.pipe_err[1]);
    }

    fn child_set_hostname(&mut self) -> Result<(), Error> {
        let hostname = match self.config.hostname {
            Some(ref h) => h,
            None => "sandbox",
        };

        try!(sethostname(hostname.as_ref()));

        Ok(())
    }

    fn child_set_mounts(&mut self) -> Result<(), Error> {
        // Avoid propagating mounts to or from the parent's mount namespace.
        try!(mount::mount::<str, str, str, str>(
            None,
            "/",
            None,
            mount::MS_PRIVATE | mount::MS_REC,
            None
        ));

        // Turn the directory into a bind mount
        try!(mount::mount::<_, _, _, str>(
            Some(&*self.chroot),
            &*self.chroot,
            Some("bind"),
            mount::MS_BIND | mount::MS_REC,
            None
        ));

        // Re-mount as read-only
        try!(mount::mount::<_, _, _, str>(
            Some(&*self.chroot),
            &*self.chroot,
            Some("bind"),
            mount::MS_BIND | mount::MS_REMOUNT | mount::MS_RDONLY | mount::MS_REC,
            None
        ));

        if self.config.mount_proc {
            let proc_path = self.config.chroot.join("proc");

            try!(mount::mount::<str, _, _, str>(
                None,
                &*proc_path,
                Some("proc"),
                mount::MS_NOSUID | mount::MS_NOEXEC | mount::MS_NODEV,
                None
            ));
        }

        if self.config.mount_dev {
            let dev_path = self.config.chroot.join("dev");

            try!(mount::mount::<str, _, _, str>(
                None,
                &*dev_path,
                Some("devtmpfs"),
                mount::MS_NOSUID | mount::MS_NOEXEC,
                None
            ));
        }

        let shm_path = self.config.chroot.join("dev").join("shm");
        let res = mount::mount::<str, _, _, str>(
            None,
            &*shm_path,
            Some("tmpfs"),
            mount::MS_NOSUID | mount::MS_NOEXEC,
            None
        );
        match res {
            Ok(..) => {},

            // Ignore 'file not found' errors.
            Err(nix::Error::Sys(nix::Errno::ENOENT)) => {},

            Err(e) => {
                return Err(Error::NixError(e));
            },
        }

        let tmp_path = self.config.chroot.join("tmp");
        let res = mount::mount::<str, _, _, str>(
            None,
            &*tmp_path,
            Some("tmpfs"),
            mount::MS_NOSUID | mount::MS_NOEXEC,
            None
        );
        match res {
            Ok(..) => {},

            // Ignore 'file not found' errors.
            Err(nix::Error::Sys(nix::Errno::ENOENT)) => {},

            Err(e) => {
                return Err(Error::NixError(e));
            },
        }

        // TODO: custom bind mounts

        // Preserve a reference to the target directory
        try!(chdir(self.config.chroot));

        // Make the working directory into the root of the mount namespace.
        try!(mount::mount::<_, _, str, str>(
            Some("."),
            "/",
            None,
            mount::MS_MOVE,
            None
        ));

        // All done with mounts!
        Ok(())
    }

    fn child_do_chroot(&mut self) -> Result<(), Error> {
        try!(chroot("."));
        try!(chdir("/"));

        Ok(())
    }

    fn child_handle_username(&mut self) -> Result<(), Error> {
        // Get information about the user.
        let user = unsafe { ffiext::getpwnam(self.username.as_ptr()) };
        if user.is_null() {
            if errno() != 0 {
                return Err(Error::PosixError("getpwnam", errno()));
            } else {
                return Err(Error::Other("no password entry exists for the given user"));
            }
        }

        let user = unsafe { *user };
        let dir = unsafe { CStr::from_ptr(user.pw_dir) };

        // Mount the user's home directory as temporary
        try!(mount::mount::<str, _, _, str>(
            None,
            dir,
            Some("tmpfs"),
            mount::MS_NOSUID | mount::MS_NODEV,
            None
        ));

        // Switch to the directory, like a login shell.
        try!(chdir(dir));

        // Create a new session.
        ptry!(setsid, libc::setsid());

        // Reset groups, UID, GID.
        ptry!(initgroups, ffiext::initgroups(self.username.as_ptr(), user.pw_gid));
        ptry!(setresgid, ffiext::setresgid(user.pw_gid, user.pw_gid, user.pw_gid));
        ptry!(setresuid, ffiext::setresuid(user.pw_uid, user.pw_uid, user.pw_uid));

        Ok(())
    }

    fn run_parent(&mut self, child_pid: libc::pid_t) -> Result<(), Error> {
        println!("child pid is: {}", child_pid);

        // TODO: want to run the epoll loop here
        panic!("todo - parent");
    }
}
