use libc;


// From #include <linux/prctl.h>
pub const PR_SET_PDEATHSIG: libc::c_int = 1;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct passwd {
    pub pw_name: *const libc::c_char,       /* username */
    pub pw_passwd: *const libc::c_char,     /* user password */
    pub pw_uid: libc::uid_t,                /* user ID */
    pub pw_gid: libc::gid_t,                /* group ID */
    pub pw_gecos: *const libc::c_char,      /* user information */
    pub pw_dir: *const libc::c_char,        /* home directory */
    pub pw_shell: *const libc::c_char,      /* shell program */
}

// From #include <unistd.h> on modern Linux
extern {
    pub fn execvpe(file: *const libc::c_char, argv: *const *const libc::c_char,
                   envp: *const *const libc::c_char) -> libc::c_int;

    pub fn getpwnam(name: *const libc::c_char) -> *const passwd;

    pub fn initgroups(user: *const libc::c_char, group: libc::gid_t) -> libc::c_int;
    pub fn setresgid(rgid: libc::gid_t, egid: libc::gid_t, sgid: libc::gid_t) -> libc::c_int;
    pub fn setresuid(rgid: libc::uid_t, egid: libc::uid_t, sgid: libc::uid_t) -> libc::c_int;
}
