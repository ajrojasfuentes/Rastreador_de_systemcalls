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
        // Núcleo muy común
        m.insert(SYS_read as u64, "read");
        m.insert(SYS_write as u64, "write");
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
        m.insert(SYS_nanosleep as u64, "nanosleep");
        m.insert(SYS_getrandom as u64, "getrandom");
        m.insert(SYS_rseq as u64, "rseq");
        m.insert(SYS_uname as u64, "uname");
        m.insert(SYS_getcwd as u64, "getcwd");
        m.insert(SYS_pipe2 as u64, "pipe2");
        m.insert(SYS_dup as u64, "dup");
        m.insert(SYS_dup2 as u64, "dup2");
        m.insert(SYS_dup3 as u64, "dup3");
        m.insert(SYS_fcntl as u64, "fcntl");
        m.insert(SYS_ioctl as u64, "ioctl");
        m.insert(SYS_sendto as u64, "sendto");
        m.insert(SYS_recvfrom as u64, "recvfrom");
        m.insert(SYS_socket as u64, "socket");
        m.insert(SYS_connect as u64, "connect");
        m.insert(SYS_bind as u64, "bind");
        m.insert(SYS_listen as u64, "listen");
        m.insert(SYS_accept4 as u64, "accept4");
        m.insert(SYS_shutdown as u64, "shutdown");
        m.insert(SYS_getsockname as u64, "getsockname");
        m.insert(SYS_getpeername as u64, "getpeername");
        m.insert(SYS_sendmsg as u64, "sendmsg");
        m.insert(SYS_recvmsg as u64, "recvmsg");
        m.insert(SYS_madvise as u64, "madvise");
        m.insert(SYS_mremap as u64, "mremap");
        m.insert(SYS_open as u64, "open"); // en x86_64 suele redirigirse a openat
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
