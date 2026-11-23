//! containerd's default seccomp profile (contrib/seccomp.DefaultProfile in
//! the containerd v2 module Armada pins), as data plus its choices by
//! architecture, kernel version, and bounding capabilities.

use super::spec::{Seccomp, SeccompArg, Syscall};

/// The syscalls every container may make (the profile's first rule).
const ALLOWED: &[&str] = &[
    "accept",
    "accept4",
    "access",
    "adjtimex",
    "alarm",
    "bind",
    "brk",
    "cachestat",
    "capget",
    "capset",
    "chdir",
    "chmod",
    "chown",
    "chown32",
    "clock_adjtime",
    "clock_adjtime64",
    "clock_getres",
    "clock_getres_time64",
    "clock_gettime",
    "clock_gettime64",
    "clock_nanosleep",
    "clock_nanosleep_time64",
    "close",
    "close_range",
    "connect",
    "copy_file_range",
    "creat",
    "dup",
    "dup2",
    "dup3",
    "epoll_create",
    "epoll_create1",
    "epoll_ctl",
    "epoll_ctl_old",
    "epoll_pwait",
    "epoll_pwait2",
    "epoll_wait",
    "epoll_wait_old",
    "eventfd",
    "eventfd2",
    "execve",
    "execveat",
    "exit",
    "exit_group",
    "faccessat",
    "faccessat2",
    "fadvise64",
    "fadvise64_64",
    "fallocate",
    "fanotify_mark",
    "fchdir",
    "fchmod",
    "fchmodat",
    "fchmodat2",
    "fchown",
    "fchown32",
    "fchownat",
    "fcntl",
    "fcntl64",
    "fdatasync",
    "fgetxattr",
    "flistxattr",
    "flock",
    "fork",
    "fremovexattr",
    "fsetxattr",
    "fstat",
    "fstat64",
    "fstatat64",
    "fstatfs",
    "fstatfs64",
    "fsync",
    "ftruncate",
    "ftruncate64",
    "futex",
    "futex_requeue",
    "futex_time64",
    "futex_wait",
    "futex_waitv",
    "futex_wake",
    "futimesat",
    "getcpu",
    "getcwd",
    "getdents",
    "getdents64",
    "getegid",
    "getegid32",
    "geteuid",
    "geteuid32",
    "getgid",
    "getgid32",
    "getgroups",
    "getgroups32",
    "getitimer",
    "getpeername",
    "getpgid",
    "getpgrp",
    "getpid",
    "getppid",
    "getpriority",
    "getrandom",
    "getresgid",
    "getresgid32",
    "getresuid",
    "getresuid32",
    "getrlimit",
    "get_robust_list",
    "getrusage",
    "getsid",
    "getsockname",
    "getsockopt",
    "get_thread_area",
    "gettid",
    "gettimeofday",
    "getuid",
    "getuid32",
    "getxattr",
    "getxattrat",
    "inotify_add_watch",
    "inotify_init",
    "inotify_init1",
    "inotify_rm_watch",
    "io_cancel",
    "ioctl",
    "io_destroy",
    "io_getevents",
    "io_pgetevents",
    "io_pgetevents_time64",
    "ioprio_get",
    "ioprio_set",
    "io_setup",
    "io_submit",
    "ipc",
    "kill",
    "landlock_add_rule",
    "landlock_create_ruleset",
    "landlock_restrict_self",
    "lchown",
    "lchown32",
    "lgetxattr",
    "link",
    "linkat",
    "listen",
    "listmount",
    "listxattr",
    "listxattrat",
    "llistxattr",
    "_llseek",
    "lremovexattr",
    "lseek",
    "lsetxattr",
    "lsm_get_self_attr",
    "lsm_list_modules",
    "lsm_set_self_attr",
    "lstat",
    "lstat64",
    "madvise",
    "membarrier",
    "memfd_create",
    "memfd_secret",
    "mincore",
    "mkdir",
    "mkdirat",
    "mknod",
    "mknodat",
    "mlock",
    "mlock2",
    "mlockall",
    "map_shadow_stack",
    "mmap",
    "mmap2",
    "mprotect",
    "mq_getsetattr",
    "mq_notify",
    "mq_open",
    "mq_timedreceive",
    "mq_timedreceive_time64",
    "mq_timedsend",
    "mq_timedsend_time64",
    "mq_unlink",
    "mremap",
    "mseal",
    "msgctl",
    "msgget",
    "msgrcv",
    "msgsnd",
    "msync",
    "munlock",
    "munlockall",
    "munmap",
    "name_to_handle_at",
    "nanosleep",
    "newfstatat",
    "_newselect",
    "open",
    "openat",
    "openat2",
    "pause",
    "pidfd_open",
    "pidfd_send_signal",
    "pipe",
    "pipe2",
    "pkey_alloc",
    "pkey_free",
    "pkey_mprotect",
    "poll",
    "ppoll",
    "ppoll_time64",
    "prctl",
    "pread64",
    "preadv",
    "preadv2",
    "prlimit64",
    "process_mrelease",
    "pselect6",
    "pselect6_time64",
    "pwrite64",
    "pwritev",
    "pwritev2",
    "read",
    "readahead",
    "readlink",
    "readlinkat",
    "readv",
    "recv",
    "recvfrom",
    "recvmmsg",
    "recvmmsg_time64",
    "recvmsg",
    "remap_file_pages",
    "removexattr",
    "removexattrat",
    "rename",
    "renameat",
    "renameat2",
    "restart_syscall",
    "rmdir",
    "rseq",
    "rt_sigaction",
    "rt_sigpending",
    "rt_sigprocmask",
    "rt_sigqueueinfo",
    "rt_sigreturn",
    "rt_sigsuspend",
    "rt_sigtimedwait",
    "rt_sigtimedwait_time64",
    "rt_tgsigqueueinfo",
    "sched_getaffinity",
    "sched_getattr",
    "sched_getparam",
    "sched_get_priority_max",
    "sched_get_priority_min",
    "sched_getscheduler",
    "sched_rr_get_interval",
    "sched_rr_get_interval_time64",
    "sched_setaffinity",
    "sched_setattr",
    "sched_setparam",
    "sched_setscheduler",
    "sched_yield",
    "seccomp",
    "select",
    "semctl",
    "semget",
    "semop",
    "semtimedop",
    "semtimedop_time64",
    "send",
    "sendfile",
    "sendfile64",
    "sendmmsg",
    "sendmsg",
    "sendto",
    "setfsgid",
    "setfsgid32",
    "setfsuid",
    "setfsuid32",
    "setgid",
    "setgid32",
    "setgroups",
    "setgroups32",
    "setitimer",
    "setpgid",
    "setpriority",
    "setregid",
    "setregid32",
    "setresgid",
    "setresgid32",
    "setresuid",
    "setresuid32",
    "setreuid",
    "setreuid32",
    "setrlimit",
    "set_robust_list",
    "setsid",
    "setsockopt",
    "set_thread_area",
    "set_tid_address",
    "setuid",
    "setuid32",
    "setxattr",
    "setxattrat",
    "shmat",
    "shmctl",
    "shmdt",
    "shmget",
    "shutdown",
    "sigaltstack",
    "signalfd",
    "signalfd4",
    "sigprocmask",
    "sigreturn",
    "socketcall",
    "socketpair",
    "splice",
    "stat",
    "stat64",
    "statfs",
    "statfs64",
    "statmount",
    "statx",
    "symlink",
    "symlinkat",
    "sync",
    "sync_file_range",
    "syncfs",
    "sysinfo",
    "tee",
    "tgkill",
    "time",
    "timer_create",
    "timer_delete",
    "timer_getoverrun",
    "timer_gettime",
    "timer_gettime64",
    "timer_settime",
    "timer_settime64",
    "timerfd_create",
    "timerfd_gettime",
    "timerfd_gettime64",
    "timerfd_settime",
    "timerfd_settime64",
    "times",
    "tkill",
    "truncate",
    "truncate64",
    "ugetrlimit",
    "umask",
    "uname",
    "unlink",
    "unlinkat",
    "uretprobe",
    "utime",
    "utimensat",
    "utimensat_time64",
    "utimes",
    "vfork",
    "vmsplice",
    "wait4",
    "waitid",
    "waitpid",
    "write",
    "writev",
];

/// allowedSocketDomains, as golang.org/x/sys/unix numbers them on Linux;
/// AF_ALG (38) and AF_VSOCK (40) are left out, as upstream leaves them.
const SOCKET_DOMAINS: &[u64] = &[
    1,  // AF_UNIX
    2,  // AF_INET
    3,  // AF_AX25
    4,  // AF_IPX
    5,  // AF_APPLETALK
    6,  // AF_NETROM
    7,  // AF_BRIDGE
    8,  // AF_ATMPVC
    9,  // AF_X25
    10, // AF_INET6
    11, // AF_ROSE
    12, // AF_DECnet
    13, // AF_NETBEUI
    14, // AF_SECURITY
    15, // AF_KEY
    16, // AF_NETLINK
    17, // AF_PACKET
    18, // AF_ASH
    19, // AF_ECONET
    20, // AF_ATMSVC
    21, // AF_RDS
    22, // AF_SNA
    23, // AF_IRDA
    24, // AF_PPPOX
    25, // AF_WANPIPE
    26, // AF_LLC
    27, // AF_IB
    28, // AF_MPLS
    29, // AF_CAN
    30, // AF_TIPC
    31, // AF_BLUETOOTH
    32, // AF_IUCV
    33, // AF_RXRPC
    34, // AF_ISDN
    35, // AF_PHONET
    36, // AF_IEEE802154
    37, // AF_CAIF
    39, // AF_NFC
    41, // AF_KCM
    42, // AF_QIPCRTR
    43, // AF_SMC
    44, // AF_XDP
    45, // AF_MCTP
];

const AF_UNIX: u64 = 1;
const ENOSYS: u32 = 38;
const CLONE_NAMESPACES: u64 = 0x0002_0000 // CLONE_NEWNS
    | 0x0400_0000 // CLONE_NEWUTS
    | 0x0800_0000 // CLONE_NEWIPC
    | 0x1000_0000 // CLONE_NEWUSER
    | 0x2000_0000 // CLONE_NEWPID
    | 0x4000_0000 // CLONE_NEWNET
    | 0x0200_0000; // CLONE_NEWCGROUP

fn allow(names: &[&str]) -> Syscall {
    Syscall {
        names: names.iter().map(|s| s.to_string()).collect(),
        action: "SCMP_ACT_ALLOW".into(),
        errno_ret: None,
        args: Vec::new(),
    }
}

fn allow_arg(name: &str, index: u64, value: u64, op: &str) -> Syscall {
    Syscall {
        args: vec![SeccompArg {
            index,
            value,
            value_two: 0,
            op: op.into(),
        }],
        ..allow(&[name])
    }
}

/// arches(): the seccomp architectures of a Go architecture.
fn arches(goarch: &str) -> Vec<String> {
    let a: &[&str] = match goarch {
        "amd64" => &["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
        "arm64" => &["SCMP_ARCH_ARM", "SCMP_ARCH_AARCH64"],
        "mips64" | "mips64n32" => &["SCMP_ARCH_MIPS", "SCMP_ARCH_MIPS64", "SCMP_ARCH_MIPS64N32"],
        "mipsel64" | "mipsel64n32" => &[
            "SCMP_ARCH_MIPSEL",
            "SCMP_ARCH_MIPSEL64",
            "SCMP_ARCH_MIPSEL64N32",
        ],
        "s390x" => &["SCMP_ARCH_S390", "SCMP_ARCH_S390X"],
        "riscv64" => &["SCMP_ARCH_RISCV64"],
        "loong64" => &["SCMP_ARCH_LOONGARCH64"],
        _ => &[],
    };
    a.iter().map(|s| s.to_string()).collect()
}

/// socketSyscalls: AF_UNIX and the domains right after it as one
/// "less than" rule, the rest one equality rule each.
fn socket_syscalls() -> Vec<Syscall> {
    let mut domains = SOCKET_DOMAINS.to_vec();
    domains.sort_unstable();
    let mut out = Vec::new();
    let mut rest: &[u64] = &domains;
    if domains.len() > 1 && domains[0] == AF_UNIX && domains[1] == domains[0] + 1 {
        let mut last = 1;
        while last + 1 < domains.len() && domains[last + 1] == domains[last] + 1 {
            last += 1;
        }
        out.push(allow_arg("socket", 0, domains[last] + 1, "SCMP_CMP_LT"));
        rest = &domains[last + 1..];
    }
    for &d in rest {
        out.push(allow_arg("socket", 0, d, "SCMP_CMP_EQ"));
    }
    out
}

/// DefaultProfile for a process with these bounding capabilities on goarch
/// (Go's runtime.GOARCH names), on a kernel at least 4.8 or not
/// (kernelversion.GreaterEqualThan; false when unreadable, as upstream).
pub fn default_profile(bounding: &[String], goarch: &str, kernel_4_8: bool) -> Seccomp {
    let mut syscalls = vec![allow(ALLOWED)];
    syscalls.extend(socket_syscalls());
    for v in [0x0, 0x0008, 0x20000, 0x20008, 0xffff_ffff] {
        syscalls.push(allow_arg("personality", 0, v, "SCMP_CMP_EQ"));
    }
    if kernel_4_8 {
        syscalls.push(allow(&["process_vm_readv", "process_vm_writev", "ptrace"]));
    }
    match goarch {
        "ppc64le" => syscalls.push(allow(&["sync_file_range2", "swapcontext"])),
        "arm" | "arm64" => syscalls.push(allow(&[
            "arm_fadvise64_64",
            "arm_sync_file_range",
            "sync_file_range2",
            "breakpoint",
            "cacheflush",
            "set_tls",
        ])),
        "amd64" => syscalls.push(allow(&["arch_prctl", "modify_ldt"])),
        "386" => syscalls.push(allow(&["modify_ldt"])),
        "s390" | "s390x" => syscalls.push(allow(&[
            "s390_pci_mmio_read",
            "s390_pci_mmio_write",
            "s390_runtime_instr",
        ])),
        "riscv64" => syscalls.push(allow(&["riscv_flush_icache", "riscv_hwprobe"])),
        _ => {}
    }
    let mut admin = false;
    for c in bounding {
        match c.as_str() {
            "CAP_DAC_READ_SEARCH" => syscalls.push(allow(&["open_by_handle_at"])),
            "CAP_SYS_ADMIN" => {
                admin = true;
                syscalls.push(allow(&[
                    "bpf",
                    "clone",
                    "clone3",
                    "fanotify_init",
                    "fsconfig",
                    "fsmount",
                    "fsopen",
                    "fspick",
                    "lookup_dcookie",
                    "mount",
                    "mount_setattr",
                    "move_mount",
                    "open_tree",
                    "perf_event_open",
                    "quotactl",
                    "quotactl_fd",
                    "setdomainname",
                    "sethostname",
                    "setns",
                    "syslog",
                    "umount",
                    "umount2",
                    "unshare",
                ]))
            }
            "CAP_SYS_BOOT" => syscalls.push(allow(&["reboot"])),
            "CAP_SYS_CHROOT" => syscalls.push(allow(&["chroot"])),
            "CAP_SYS_MODULE" => {
                syscalls.push(allow(&["delete_module", "init_module", "finit_module"]))
            }
            "CAP_SYS_PACCT" => syscalls.push(allow(&["acct"])),
            "CAP_SYS_PTRACE" => syscalls.push(allow(&[
                "kcmp",
                "pidfd_getfd",
                "process_madvise",
                "process_vm_readv",
                "process_vm_writev",
                "ptrace",
            ])),
            "CAP_SYS_RAWIO" => syscalls.push(allow(&["iopl", "ioperm"])),
            "CAP_SYS_TIME" => syscalls.push(allow(&[
                "settimeofday",
                "stime",
                "clock_settime",
                "clock_settime64",
            ])),
            "CAP_SYS_TTY_CONFIG" => syscalls.push(allow(&["vhangup"])),
            "CAP_SYS_NICE" => syscalls.push(allow(&[
                "get_mempolicy",
                "mbind",
                "set_mempolicy",
                "set_mempolicy_home_node",
            ])),
            "CAP_SYSLOG" => syscalls.push(allow(&["syslog"])),
            "CAP_BPF" => syscalls.push(allow(&["bpf"])),
            "CAP_PERFMON" => syscalls.push(allow(&["perf_event_open"])),
            _ => {}
        }
    }
    if !admin {
        let index = if matches!(goarch, "s390" | "s390x") {
            1
        } else {
            0
        };
        syscalls.push(Syscall {
            args: vec![SeccompArg {
                index,
                value: CLONE_NAMESPACES,
                value_two: 0,
                op: "SCMP_CMP_MASKED_EQ".into(),
            }],
            ..allow(&["clone"])
        });
        syscalls.push(Syscall {
            names: vec!["clone3".into()],
            action: "SCMP_ACT_ERRNO".into(),
            errno_ret: Some(ENOSYS),
            args: Vec::new(),
        });
    }
    Seccomp {
        default_action: "SCMP_ACT_ERRNO".into(),
        architectures: arches(goarch),
        syscalls,
    }
}

/// kernelversion.GreaterEqualThan(4.8) on this machine: uname's release
/// read as "%d.%d"; false when it does not read.
pub fn kernel_at_least_4_8() -> bool {
    // SAFETY: uname fills the zeroed struct it is given.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return false;
    }
    let release: Vec<u8> = u
        .release
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    match scan_two(&release) {
        Some((kernel, major)) => kernel > 4 || (kernel == 4 && major >= 8),
        None => false,
    }
}

/// fmt.Sscanf(release, "%d.%d"): two decimal numbers (each with an
/// optional sign) around a dot.
fn scan_two(s: &[u8]) -> Option<(i64, i64)> {
    let (a, rest) = scan_int(s)?;
    let rest = rest.strip_prefix(b".")?;
    let (b, _) = scan_int(rest)?;
    Some((a, b))
}

fn scan_int(s: &[u8]) -> Option<(i64, &[u8])> {
    let (neg, digits) = match s.first() {
        Some(b'+') => (false, &s[1..]),
        Some(b'-') => (true, &s[1..]),
        _ => (false, s),
    };
    let n = digits.iter().take_while(|c| c.is_ascii_digit()).count();
    if n == 0 {
        return None;
    }
    let v: i64 = std::str::from_utf8(&digits[..n]).ok()?.parse().ok()?;
    Some((if neg { -v } else { v }, &digits[n..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockets_collapse_to_the_first_gap() {
        let s = socket_syscalls();
        assert_eq!(s[0].args[0].value, 38);
        assert_eq!(s[0].args[0].op, "SCMP_CMP_LT");
        let rest: Vec<u64> = s[1..].iter().map(|c| c.args[0].value).collect();
        assert_eq!(rest, [39, 41, 42, 43, 44, 45]);
    }

    #[test]
    fn admin_drops_the_clone_rules() {
        let p = default_profile(&["CAP_SYS_ADMIN".into()], "amd64", true);
        assert!(
            !p.syscalls
                .iter()
                .any(|s| s.names == ["clone3"] && s.errno_ret.is_some())
        );
        let p = default_profile(&[], "arm64", true);
        assert_eq!(p.syscalls.last().unwrap().errno_ret, Some(ENOSYS));
        assert_eq!(p.architectures, ["SCMP_ARCH_ARM", "SCMP_ARCH_AARCH64"]);
    }

    #[test]
    fn reads_kernel_releases() {
        assert_eq!(scan_two(b"7.0.0-30-generic"), Some((7, 0)));
        assert_eq!(scan_two(b"4.8"), Some((4, 8)));
        assert_eq!(scan_two(b"x"), None);
    }
}
