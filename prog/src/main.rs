use libc;
use std::env;
use std::ffi::{CString, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::ptr;

fn main() -> std::io::Result<()> {
    println!("-- sysplay: inicio --");

    // 1) CWD y directorio temporal
    let orig_cwd = env::current_dir()?;
    let tmpdir = PathBuf::from(format!("/tmp/rt_rust_{}", std::process::id()));
    fs::create_dir_all(&tmpdir)?;
    env::set_current_dir(&tmpdir)?;

    // 2) Archivo: crear, escribir, fsync, lseek, leer, fstat
    let mut f = OpenOptions::new().create(true).read(true).write(true).open("a.txt")?;
    writeln!(f, "Hola desde Rust @ {}", chrono_secs())?;
    f.sync_all()?; // fsync/FDatasync a nivel de OS

    let fd = f.as_raw_fd();
    unsafe {
        // lseek al inicio
        if libc::lseek(fd, 0, libc::SEEK_SET) < 0 {
            panic!("lseek falló");
        }
        // fstat
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st as *mut _) < 0 {
            panic!("fstat falló");
        }
    }

    let mut contents = String::new();
    f.read_to_string(&mut contents)?;
    print!("Leído del archivo: {}", contents);

    // 3) Memoria: mmap anónimo, escribir, mprotect RO, leer, munmap
    let len: usize = 4096;
    let addr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if addr == libc::MAP_FAILED {
        panic!("mmap falló");
    }
    unsafe {
        let slice = std::slice::from_raw_parts_mut(addr as *mut u8, len);
        slice[0..11].copy_from_slice(b"hola-mmap!\n");
        // volver de RW -> R
        if libc::mprotect(addr, len, libc::PROT_READ) != 0 {
            panic!("mprotect falló");
        }
        // leer en RO
        let s = std::str::from_utf8_unchecked(&slice[0..11]);
        print!("Desde mmap: {}", s);
        if libc::munmap(addr, len) != 0 {
            panic!("munmap falló");
        }
    }

    // 4) Pipe + poll
    let mut pfds = [0i32; 2];
    let rc = unsafe { libc::pipe2(pfds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        panic!("pipe2 falló");
    }
    let (rfd, wfd) = (pfds[0], pfds[1]);
    let msg = b"hola-pipe\n";
    let n = unsafe { libc::write(wfd, msg.as_ptr() as *const _, msg.len()) };
    assert_eq!(n, msg.len() as isize);

    // poll lectura disponible
    let mut pfd = libc::pollfd { fd: rfd, events: libc::POLLIN, revents: 0 };
    let prc = unsafe { libc::poll(&mut pfd as *mut _, 1, 1000) };
    assert!(prc >= 0);

    let mut buf = [0u8; 64];
    let rn = unsafe { libc::read(rfd, buf.as_mut_ptr() as *mut _, buf.len()) };
    assert!(rn > 0);
    print!("Desde pipe: {}", String::from_utf8_lossy(&buf[..rn as usize]));

    unsafe { libc::close(rfd); libc::close(wfd); }

    // 5) Socket UNIX (socketpair) + send/recv
    let mut sv = [0i32; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
    if rc != 0 { panic!("socketpair falló"); }
    let (s0, s1) = (sv[0], sv[1]);

    let data = b"hola-sock\n";
    let wn = unsafe { libc::write(s0, data.as_ptr() as *const _, data.len()) };
    assert_eq!(wn, data.len() as isize);
    let rn = unsafe { libc::read(s1, buf.as_mut_ptr() as *mut _, buf.len()) };
    assert!(rn > 0);
    print!("Desde socketpair: {}", String::from_utf8_lossy(&buf[..rn as usize]));
    unsafe { libc::close(s0); libc::close(s1); }

    // 6) getrandom
    let mut r = [0u8; 16];
    let gr = unsafe { libc::getrandom(r.as_mut_ptr() as *mut _, r.len(), 0) };
    assert_eq!(gr, r.len() as isize);
    println!("getrandom(16) ok: {:02x?}", &r);

    // 7) nanosleep ~50ms
    let ts = libc::timespec { tv_sec: 0, tv_nsec: 50_000_000 };
    unsafe { libc::nanosleep(&ts, ptr::null_mut()); }

    // 8) readlink /proc/self/exe
    let mut pathbuf = vec![0u8; 4096];
    let cpath = CString::new("/proc/self/exe").unwrap();
    let rn = unsafe {
        libc::readlink(
            cpath.as_ptr(),
            pathbuf.as_mut_ptr() as *mut _,
            pathbuf.len(),
        )
    };
    if rn > 0 {
        let p = String::from_utf8_lossy(&pathbuf[..rn as usize]);
        println!("readlink /proc/self/exe -> {}", p);
    }

    // 9) limpieza
    drop(f);
    fs::remove_file("a.txt").ok();
    env::set_current_dir(&orig_cwd)?;
    fs::remove_dir_all(&tmpdir).ok();

    println!("-- sysplay: fin --");
    Ok(())
}

fn chrono_secs() -> u64 {
    // evitar dependencias: simple time_t
    unsafe { libc::time(ptr::null_mut()) as u64 }
}
