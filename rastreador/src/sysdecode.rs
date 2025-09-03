use libc;
use nix::sys::ptrace;
use nix::unistd::Pid;
use std::collections::HashMap;
use std::io;
use std::mem::size_of;
use once_cell::sync::Lazy;

// === Nombres de syscalls: tabla parcial común en x86_64 Linux ===
// Fallback: "sys_<num>" si no está en la tabla.
pub fn syscall_name(n: u64) -> String {
    static INIT: Lazy<HashMap<u64, &'static str>> = once_cell::sync::Lazy::new(|| {
        use libc::*;
        let mut m = HashMap::new();
        // Núcleo
        m.insert(SYS_read as u64, "read");
        m.insert(SYS_write as u64, "write");
        m.insert(SYS_open as u64, "open");
        m.insert(SYS_openat as u64, "openat");
        m.insert(SYS_close as u64, "close");
        m.insert(SYS_statx as u64, "statx");
        m.insert(SYS_fstat as u64, "fstat");
        m.insert(SYS_lseek as u64, "lseek");
        m.insert(SYS_mmap as u64, "mmap");
        m.insert(SYS_munmap as u64, "munmap");
        m.insert(SYS_brk as u64, "brk");
        m.insert(SYS_mprotect as u64, "mprotect");
        m.insert(SYS_rt_sigaction as u64, "rt_sigaction");
        m.insert(SYS_rt_sigprocmask as u64, "rt_sigprocmask");
        m.insert(SYS_rt_sigreturn as u64, "rt_sigreturn");
        m.insert(SYS_clone as u64, "clone");
        m.insert(SYS_fork as u64, "fork");
        m.insert(SYS_vfork as u64, "vfork");
        m.insert(SYS_execve as u64, "execve");
        m.insert(SYS_exit as u64, "exit");
        m.insert(SYS_exit_group as u64, "exit_group");
        m.insert(SYS_wait4 as u64, "wait4");
        m.insert(SYS_kill as u64, "kill");
        m.insert(SYS_getpid as u64, "getpid");
        m.insert(SYS_getppid as u64, "getppid");
        m.insert(SYS_gettid as u64, "gettid");
        m.insert(SYS_arch_prctl as u64, "arch_prctl");
        m.insert(SYS_set_tid_address as u64, "set_tid_address");
        m.insert(SYS_set_robust_list as u64, "set_robust_list");
        m.insert(SYS_prlimit64 as u64, "prlimit64");
        m.insert(SYS_clock_gettime as u64, "clock_gettime");
        m.insert(SYS_clock_settime as u64, "clock_settime");
        m.insert(SYS_clock_getres as u64, "clock_getres");
        m.insert(SYS_clock_nanosleep as u64, "clock_nanosleep");
        m.insert(SYS_nanosleep as u64, "nanosleep");
        m.insert(SYS_gettimeofday as u64, "gettimeofday");
        m.insert(SYS_settimeofday as u64, "settimeofday");
        m.insert(SYS_time as u64, "time");
        m.insert(SYS_times as u64, "times");
        m.insert(SYS_getrandom as u64, "getrandom");
        m.insert(SYS_rseq as u64, "rseq");
        m.insert(SYS_uname as u64, "uname");
        m.insert(SYS_getcwd as u64, "getcwd");
        m.insert(SYS_chdir as u64, "chdir");
        m.insert(SYS_fchdir as u64, "fchdir");
        m.insert(SYS_umask as u64, "umask");
        m.insert(SYS_getuid as u64, "getuid");
        m.insert(SYS_geteuid as u64, "geteuid");
        m.insert(SYS_getgid as u64, "getgid");
        m.insert(SYS_getegid as u64, "getegid");
        m.insert(SYS_setuid as u64, "setuid");
        m.insert(SYS_setgid as u64, "setgid");
        m.insert(SYS_setresuid as u64, "setresuid");
        m.insert(SYS_getresuid as u64, "getresuid");
        m.insert(SYS_setresgid as u64, "setresgid");
        m.insert(SYS_getresgid as u64, "getresgid");
        m.insert(SYS_setfsuid as u64, "setfsuid");
        m.insert(SYS_setfsgid as u64, "setfsgid");
        m.insert(SYS_personality as u64, "personality");
        m.insert(SYS_getrusage as u64, "getrusage");
        m.insert(SYS_sysinfo as u64, "sysinfo");
        m.insert(SYS_prctl as u64, "prctl");

        // Archivos y directorios
        m.insert(SYS_access as u64, "access");
        m.insert(SYS_faccessat as u64, "faccessat");
        m.insert(SYS_readlink as u64, "readlink");
        m.insert(SYS_readlinkat as u64, "readlinkat");
        m.insert(SYS_link as u64, "link");
        m.insert(SYS_linkat as u64, "linkat");
        m.insert(SYS_symlink as u64, "symlink");
        m.insert(SYS_symlinkat as u64, "symlinkat");
        m.insert(SYS_unlink as u64, "unlink");
        m.insert(SYS_unlinkat as u64, "unlinkat");
        m.insert(SYS_mkdir as u64, "mkdir");
        m.insert(SYS_mkdirat as u64, "mkdirat");
        m.insert(SYS_rmdir as u64, "rmdir");
        m.insert(SYS_mknod as u64, "mknod");
        m.insert(SYS_mknodat as u64, "mknodat");
        m.insert(SYS_rename as u64, "rename");
        m.insert(SYS_renameat as u64, "renameat");
        m.insert(SYS_chroot as u64, "chroot");
        m.insert(SYS_truncate as u64, "truncate");
        m.insert(SYS_ftruncate as u64, "ftruncate");
        m.insert(SYS_chmod as u64, "chmod");
        m.insert(SYS_fchmod as u64, "fchmod");
        m.insert(SYS_fchmodat as u64, "fchmodat");
        m.insert(SYS_chown as u64, "chown");
        m.insert(SYS_fchown as u64, "fchown");
        m.insert(SYS_lchown as u64, "lchown");
        m.insert(SYS_fchownat as u64, "fchownat");
        m.insert(SYS_utimensat as u64, "utimensat");
        m.insert(SYS_getdents64 as u64, "getdents64");
        m.insert(SYS_statfs as u64, "statfs");
        m.insert(SYS_fstatfs as u64, "fstatfs");
        m.insert(SYS_sync as u64, "sync");
        m.insert(SYS_syncfs as u64, "syncfs");
        m.insert(SYS_fsync as u64, "fsync");
        m.insert(SYS_fdatasync as u64, "fdatasync");
        m.insert(SYS_sync_file_range as u64, "sync_file_range");
        m.insert(SYS_sendfile as u64, "sendfile");

        // I/O avanzadas
        m.insert(SYS_pread64 as u64, "pread64");
        m.insert(SYS_pwrite64 as u64, "pwrite64");
        m.insert(SYS_preadv as u64, "preadv");
        m.insert(SYS_pwritev as u64, "pwritev");
        m.insert(SYS_splice as u64, "splice");
        m.insert(SYS_tee as u64, "tee");
        m.insert(SYS_vmsplice as u64, "vmsplice");
        m.insert(SYS_copy_file_range as u64, "copy_file_range");

        // Memoria
        m.insert(SYS_madvise as u64, "madvise");
        m.insert(SYS_mremap as u64, "mremap");
        m.insert(SYS_mlock as u64, "mlock");
        m.insert(SYS_munlock as u64, "munlock");
        m.insert(SYS_mlockall as u64, "mlockall");
        m.insert(SYS_munlockall as u64, "munlockall");

        // Planificación
        m.insert(SYS_sched_yield as u64, "sched_yield");
        m.insert(SYS_sched_setparam as u64, "sched_setparam");
        m.insert(SYS_sched_getparam as u64, "sched_getparam");
        m.insert(SYS_sched_setscheduler as u64, "sched_setscheduler");
        m.insert(SYS_sched_getscheduler as u64, "sched_getscheduler");
        m.insert(SYS_sched_get_priority_max as u64, "sched_get_priority_max");
        m.insert(SYS_sched_get_priority_min as u64, "sched_get_priority_min");
        m.insert(SYS_sched_rr_get_interval as u64, "sched_rr_get_interval");
        m.insert(SYS_sched_setaffinity as u64, "sched_setaffinity");
        m.insert(SYS_sched_getaffinity as u64, "sched_getaffinity");

        // Señales
        m.insert(SYS_tgkill as u64, "tgkill");
        m.insert(SYS_tkill as u64, "tkill");
        m.insert(SYS_rt_sigsuspend as u64, "rt_sigsuspend");
        m.insert(SYS_rt_sigpending as u64, "rt_sigpending");
        m.insert(SYS_rt_sigtimedwait as u64, "rt_sigtimedwait");
        m.insert(SYS_rt_sigqueueinfo as u64, "rt_sigqueueinfo");
        m.insert(SYS_sigaltstack as u64, "sigaltstack");

        // Redes
        m.insert(SYS_socket as u64, "socket");
        m.insert(SYS_socketpair as u64, "socketpair");
        m.insert(SYS_connect as u64, "connect");
        m.insert(SYS_bind as u64, "bind");
        m.insert(SYS_listen as u64, "listen");
        m.insert(SYS_accept as u64, "accept");
        m.insert(SYS_accept4 as u64, "accept4");
        m.insert(SYS_shutdown as u64, "shutdown");
        m.insert(SYS_getsockname as u64, "getsockname");
        m.insert(SYS_getpeername as u64, "getpeername");
        m.insert(SYS_setsockopt as u64, "setsockopt");
        m.insert(SYS_getsockopt as u64, "getsockopt");
        m.insert(SYS_sendto as u64, "sendto");
        m.insert(SYS_recvfrom as u64, "recvfrom");
        m.insert(SYS_sendmsg as u64, "sendmsg");
        m.insert(SYS_recvmsg as u64, "recvmsg");
        m.insert(SYS_recvmmsg as u64, "recvmmsg");
        m.insert(SYS_sendmmsg as u64, "sendmmsg");
        m.insert(SYS_poll as u64, "poll");
        m.insert(SYS_ppoll as u64, "ppoll");
        m.insert(SYS_select as u64, "select");
        m.insert(SYS_pselect6 as u64, "pselect6");

        // epoll/inotify/eventfd/signalfd/timerfd
        m.insert(SYS_epoll_create as u64, "epoll_create");
        m.insert(SYS_epoll_create1 as u64, "epoll_create1");
        m.insert(SYS_epoll_ctl as u64, "epoll_ctl");
        m.insert(SYS_epoll_wait as u64, "epoll_wait");
        m.insert(SYS_epoll_pwait as u64, "epoll_pwait");
        m.insert(SYS_inotify_init as u64, "inotify_init");
        m.insert(SYS_inotify_init1 as u64, "inotify_init1");
        m.insert(SYS_inotify_add_watch as u64, "inotify_add_watch");
        m.insert(SYS_inotify_rm_watch as u64, "inotify_rm_watch");
        m.insert(SYS_eventfd as u64, "eventfd");
        m.insert(SYS_eventfd2 as u64, "eventfd2");
        m.insert(SYS_signalfd as u64, "signalfd");
        m.insert(SYS_signalfd4 as u64, "signalfd4");
        m.insert(SYS_timerfd_create as u64, "timerfd_create");
        m.insert(SYS_timerfd_settime as u64, "timerfd_settime");
        m.insert(SYS_timerfd_gettime as u64, "timerfd_gettime");

        // Futex y atomics
        m.insert(SYS_futex as u64, "futex");

        // FS extendido
        m.insert(SYS_getxattr as u64, "getxattr");
        m.insert(SYS_lgetxattr as u64, "lgetxattr");
        m.insert(SYS_fgetxattr as u64, "fgetxattr");
        m.insert(SYS_setxattr as u64, "setxattr");
        m.insert(SYS_lsetxattr as u64, "lsetxattr");
        m.insert(SYS_fsetxattr as u64, "fsetxattr");
        m.insert(SYS_listxattr as u64, "listxattr");
        m.insert(SYS_llistxattr as u64, "llistxattr");
        m.insert(SYS_flistxattr as u64, "flistxattr");
        m.insert(SYS_removexattr as u64, "removexattr");
        m.insert(SYS_lremovexattr as u64, "lremovexattr");
        m.insert(SYS_fremovexattr as u64, "fremovexattr");

        // Montaje y namespaces
        m.insert(SYS_mount as u64, "mount");
        m.insert(SYS_umount2 as u64, "umount2");
        m.insert(SYS_pivot_root as u64, "pivot_root");
        m.insert(SYS_unshare as u64, "unshare");
        m.insert(SYS_setns as u64, "setns");

        // Varios
        m.insert(SYS_readahead as u64, "readahead");
        m.insert(SYS_fanotify_init as u64, "fanotify_init");
        m.insert(SYS_fanotify_mark as u64, "fanotify_mark");
        m.insert(SYS_memfd_create as u64, "memfd_create");
        m.insert(SYS_name_to_handle_at as u64, "name_to_handle_at");
        m.insert(SYS_open_by_handle_at as u64, "open_by_handle_at");
        m.insert(SYS_perf_event_open as u64, "perf_event_open");
        m.insert(SYS_bpf as u64, "bpf");

        m
    });

    if let Some(&name) = INIT.get(&n) {
        name.to_string()
    } else {
        format!("sys_{}", n)
    }
}

// === Lectura segura de memoria del hijo ===
const MAX_STR: usize = 4096; // límite al leer C-strings

pub fn read_c_string(pid: Pid, addr: u64) -> io::Result<String> {
    if addr == 0 { return Ok(String::from("NULL")); }
    let word_size = size_of::<usize>();
    let mut bytes = Vec::<u8>::with_capacity(64);
    let mut p = addr;
    loop {
        let data = ptrace::read(pid, p as ptrace::AddressType)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "ptrace::read"))? as usize;
        let chunk = data.to_ne_bytes();
        for &b in &chunk {
            if b == 0 { return Ok(String::from_utf8_lossy(&bytes).into()); }
            bytes.push(b);
            if bytes.len() >= MAX_STR { return Ok(String::from_utf8_lossy(&bytes).into()); }
        }
        p = p.wrapping_add(word_size as u64);
    }
}

pub fn read_ptr(pid: Pid, addr: u64) -> io::Result<usize> {
    let data = ptrace::read(pid, addr as ptrace::AddressType)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "ptrace::read"))? as usize;
    Ok(data)
}

// === Decodificación de errno ===
pub fn decode_errno(errno: i32) -> String {
    // Lista común; si no coincide, devuelve "EPERM(1)" estilo genérico
    match errno {
        libc::EPERM => "EPERM".into(),
        libc::ENOENT => "ENOENT".into(),
        libc::ESRCH => "ESRCH".into(),
        libc::EINTR => "EINTR".into(),
        libc::EIO => "EIO".into(),
        libc::ENXIO => "ENXIO".into(),
        libc::E2BIG => "E2BIG".into(),
        libc::ENOEXEC => "ENOEXEC".into(),
        libc::EBADF => "EBADF".into(),
        libc::ECHILD => "ECHILD".into(),
        libc::EAGAIN => "EAGAIN".into(),
        libc::ENOMEM => "ENOMEM".into(),
        libc::EACCES => "EACCES".into(),
        libc::EFAULT => "EFAULT".into(),
        libc::EBUSY => "EBUSY".into(),
        libc::EEXIST => "EEXIST".into(),
        libc::EXDEV => "EXDEV".into(),
        libc::ENODEV => "ENODEV".into(),
        libc::ENOTDIR => "ENOTDIR".into(),
        libc::EISDIR => "EISDIR".into(),
        libc::EINVAL => "EINVAL".into(),
        libc::ENFILE => "ENFILE".into(),
        libc::EMFILE => "EMFILE".into(),
        libc::ENOTTY => "ENOTTY".into(),
        libc::ETXTBSY => "ETXTBSY".into(),
        libc::EFBIG => "EFBIG".into(),
        libc::ENOSPC => "ENOSPC".into(),
        libc::ESPIPE => "ESPIPE".into(),
        libc::EROFS => "EROFS".into(),
        libc::EMLINK => "EMLINK".into(),
        libc::EPIPE => "EPIPE".into(),
        libc::EDOM => "EDOM".into(),
        libc::ERANGE => "ERANGE".into(),
        libc::EDEADLK => "EDEADLK".into(),
        libc::ENAMETOOLONG => "ENAMETOOLONG".into(),
        libc::ENOLCK => "ENOLCK".into(),
        libc::ENOSYS => "ENOSYS".into(),
        libc::ENOTEMPTY => "ENOTEMPTY".into(),
        libc::ELOOP => "ELOOP".into(),
        libc::ENOMSG => "ENOMSG".into(),
        libc::EIDRM => "EIDRM".into(),
        libc::EILSEQ => "EILSEQ".into(),
        libc::EOVERFLOW => "EOVERFLOW".into(),
        _ => format!("ERR({})", errno),
    }
}

// === Flags de open/openat (parcial) ===
pub fn fmt_flags_open(flags: i32) -> String {
    use libc::*;
    let mut parts: Vec<&str> = Vec::new();
    // modo acceso
    match flags & O_ACCMODE {
        O_RDONLY => parts.push("O_RDONLY"),
        O_WRONLY => parts.push("O_WRONLY"),
        O_RDWR => parts.push("O_RDWR"),
        _ => {}
    }
    // otros
    if flags & O_CREAT != 0 { parts.push("O_CREAT"); }
    if flags & O_TRUNC != 0 { parts.push("O_TRUNC"); }
    if flags & O_APPEND != 0 { parts.push("O_APPEND"); }
    if flags & O_CLOEXEC != 0 { parts.push("O_CLOEXEC"); }
    if flags & O_EXCL != 0 { parts.push("O_EXCL"); }
    if flags & O_DIRECTORY != 0 { parts.push("O_DIRECTORY"); }
    if flags & O_NOFOLLOW != 0 { parts.push("O_NOFOLLOW"); }
    if flags & O_NONBLOCK != 0 { parts.push("O_NONBLOCK"); }
    if parts.is_empty() { return format!("0x{:x}", flags); }
    parts.join("|")
}
