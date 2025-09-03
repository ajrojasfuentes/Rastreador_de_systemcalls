use clap::{ArgAction, Parser};
use crossterm::event::{read, Event};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use libc;
use nix::sys::ptrace;
use nix::unistd::{execvp, fork, ForkResult, Pid};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::io::Write;
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use anyhow;
use nix::errno::Errno;
use nix::sys::wait::{waitpid, WaitStatus};

mod sysdecode; // helpers para nombres de syscalls y lectura de memoria del hijo
use sysdecode::{decode_errno, fmt_flags_open, read_c_string, read_ptr, syscall_name};

#[derive(Parser, Debug)]
#[command(name = "rastreador", about = "Tracer de syscalls estilo strace (simplificado)")]
struct Opts {
    /// Modo verboso: muestra cada syscall con detalles
    #[arg(short = 'v', long = "verbose", action = ArgAction::SetTrue)]
    verbose: bool,

    /// Modo muy verboso: como -v pero pausa tras cada evento
    #[arg(short = 'V', long = "very", action = ArgAction::SetTrue)]
    very_verbose: bool,

    /// Programa objetivo a ejecutar (Prog)
    #[arg(required = true)]
    prog: String,

    /// Argumentos de Prog (se pasan tal cual)
    #[arg(trailing_var_arg = true)]
    args: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let mut opts = Opts::parse();
    if opts.very_verbose {
        opts.verbose = true; // -V implica -v
    }
    ensure_prog_exists(&opts.prog)?;

    // fork + ptrace
    match unsafe { fork()? } {
        ForkResult::Child => child_exec(&opts),
        ForkResult::Parent { child } => parent_trace(child, &opts),
    }
}

fn ensure_prog_exists(p: &str) -> anyhow::Result<()> {
    // Si es ruta, verifica existencia; si es nombre, deja que execvp falle con mensaje claro
    if p.contains('/') {
        let path = Path::new(p);
        if !path.exists() {
            anyhow::bail!("El programa '{p}' no existe");
        }
    }
    Ok(())
}

fn child_exec(opts: &Opts) -> ! {
    // Activa modo TRACEME para que el padre pueda ptracear
    ptrace::traceme().expect("ptrace(TRACEME) falló");

    // Prepara argv para execvp
    let prog_c = CString::new(opts.prog.as_str()).unwrap();
    let mut argv: Vec<CString> = Vec::with_capacity(1 + opts.args.len());
    argv.push(prog_c.clone());
    for a in &opts.args {
        argv.push(CString::new(a.as_str()).unwrap());
    }

    // Ejecuta (si falla, imprime y sale)
    match execvp(&prog_c, &argv) {
        Ok(_) => unreachable!(),
        Err(e) => {
            eprintln!("execvp falló: {e}");
            std::process::exit(127);
        }
    }
}

#[derive(Default, Debug)]
struct ThreadState {
    entering: bool,           // alterna entre entrada/salida de syscall
    last_syscall: u64,        // número de syscall en entrada
}

fn parent_trace(child: Pid, opts: &Opts) -> ! {
    // Espera el primer stop (por exec/Señal)
    wait_for_any_stop(child);

    // Habilita TRACESYSGOOD para distinguir stops de syscalls
    let options = ptrace::Options::PTRACE_O_TRACESYSGOOD;
    ptrace::setoptions(child, options).expect("ptrace(SETOPTIONS)");

    // Estado por TID (aunque no seguimos forks/hilos, ser robusto no estorba)
    let mut per_tid: HashMap<Pid, ThreadState> = HashMap::new();
    let mut counts: HashMap<u64, u64> = HashMap::new();
    let mut total_calls: u64 = 0;

    // Arranca el bucle
    ptrace::syscall(child, None).expect("ptrace(SYSCALL) inicial");

    loop {
        match waitpid(None, None) {
            Ok(WaitStatus::Exited(pid, status)) => {
                // Proceso principal terminó
                if pid == child {
                    print_summary(&counts, total_calls);
                    std::process::exit(status);
                }
            }
            Ok(WaitStatus::Signaled(pid, sig, _core)) => {
                if pid == child {
                    eprintln!("[rastreador] Proceso terminó por señal {sig:?}");
                    print_summary(&counts, total_calls);
                    std::process::exit(128 + sig as i32);
                }
            }
            Ok(WaitStatus::PtraceSyscall(pid)) => {
                // Stop por entrada o salida de syscall
                let st = per_tid.entry(pid).or_insert_with(|| ThreadState { entering: true, last_syscall: 0 });
                let regs = ptrace_getregs(pid).expect("GETREGS");

                if st.entering {
                    // ENTRADA: registra número y muestra args si -v
                    let scno = regs.orig_rax as u64; // número está en ORIG_RAX al entrar
                    st.last_syscall = scno;
                    if opts.verbose {
                        log_sys_enter(pid, scno, &regs);
                        if opts.very_verbose { wait_keypress(); }
                    }
                    st.entering = false;
                } else {
                    // SALIDA: muestra retorno si -v, incrementa conteo
                    let scno = st.last_syscall;
                    let ret = regs.rax as i64; // valor de retorno
                    if opts.verbose {
                        log_sys_exit(pid, scno, ret);
                        if opts.very_verbose { wait_keypress(); }
                    }
                    *counts.entry(scno).or_insert(0) += 1;
                    total_calls += 1;
                    st.entering = true;
                }

                // Continuar
                ptrace::syscall(pid, None).unwrap();
            }
            Ok(WaitStatus::Stopped(pid, sig)) => {
                // Stop por señal distinta; reinyecta señal al hijo
                let signo = Some(sig);
                ptrace::syscall(pid, signo).unwrap();
            }
            Ok(WaitStatus::PtraceEvent(pid, sig, _code)) => {
                // No seguimos forks/hilos; solo continuar
                let signo = Some(sig);
                ptrace::syscall(pid, signo).unwrap();
            }
            Ok(other) => {
                // Otros estados (StillAlive, etc.)
                eprintln!("[rastreador] Estado: {other:?}");
            }
            Err(e) => match e {
                nix::Error::ECHILD => {
                    // Sin hijos: terminó
                    print_summary(&counts, total_calls);
                    std::process::exit(0);
                }
                _ => panic!("waitpid falló: {e}"),
            },
        }
    }
}

fn wait_for_any_stop(child: Pid) {
    loop {
        match waitpid(Some(child), None) {
            Ok(WaitStatus::Stopped(_, _)) | Ok(WaitStatus::PtraceSyscall(_)) => break,
            Ok(_) => continue,
            Err(_) => break,
        }
    }
}

fn ptrace_getregs(pid: Pid) -> nix::Result<libc::user_regs_struct> {
    ptrace::getregs(pid)
}

fn log_sys_enter(pid: Pid, scno: u64, regs: &libc::user_regs_struct) {
    let name = syscall_name(scno);
    // Registros de argumentos en x86_64 Linux
    let (a0, a1, a2, a3, a4, a5) = (regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);

    // Decodificación especial para algunas syscalls comunes
    if scno == libc::SYS_execve as u64 {
        let path = read_c_string(pid, a0).unwrap_or_else(|_| format!("<ptr 0x{a0:x}>"));
        // argv: **char -> vector de CStrings (limitado)
        let argv_preview = read_argv_preview(pid, a1, 6);
        eprintln!("→ {}(pathname=\\{:?}\\, argv={:?}, envp=0x{:x})", name, path, argv_preview, a2);
        return;
    }
    if scno == libc::SYS_openat as u64 {
        let dirfd = a0 as i64;
        let path = read_c_string(pid, a1).unwrap_or_else(|_| format!("<ptr 0x{a1:x}>"));
        let flags = a2 as i32;
        let mode = a3 as u32;
        eprintln!(
            "→ {}(dirfd={}, pathname=\\{:?}\\, flags={}, mode=0{:o})",
            name,
            dirfd,
            path,
            fmt_flags_open(flags),
            mode
        );
        return;
    }

    // Genérico (muestra hex y decimal)
    eprintln!(
        "→ {}(0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x})",
        name, a0, a1, a2, a3, a4, a5
    );
}

fn log_sys_exit(_pid: Pid, scno: u64, ret: i64) {
    let name = syscall_name(scno);
    if ret < 0 && ret >= -4095 {
        let errno = -ret as i32;
        eprintln!("← {} = -1 {}", name, decode_errno(errno));
    } else {
        eprintln!("← {} = {}", name, ret);
    }
}

fn wait_keypress() {
    eprint!("(V) Presiona cualquier tecla para continuar… ");
    let _ = io::stdout().flush();
    // Habilita modo raw para no requerir Enter
    let _ = enable_raw_mode();
    let _ = read(); // bloquea hasta cualquier evento de teclado
    let _ = disable_raw_mode();
    eprintln!("");
}

fn read_argv_preview(pid: Pid, argv_ptr: u64, max_items: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let word_size = size_of::<usize>() as u64;
    let mut p = argv_ptr;
    while i < max_items {
        match read_ptr(pid, p) {
            Ok(0) => break, // NULL termina
            Ok(s_ptr) => {
                let s = read_c_string(pid, s_ptr as u64)
                    .unwrap_or_else(|_| format!("<ptr 0x{:x}>", s_ptr));
                out.push(s);
                p += word_size;
                i += 1;
            }
            Err(_) => break,
        }
    }
    if i == max_items {
        out.push("…".to_string());
    }
    out
}

fn print_summary(counts: &HashMap<u64, u64>, total: u64) {
    use std::cmp::Reverse;
    let mut v: Vec<(u64, u64)> = counts.iter().map(|(k, c)| (*k, *c)).collect();
    v.sort_by_key(|&(_k, c)| Reverse(c));

    println!("\\n===== RESUMEN DE SYSCALLS =====");
    println!("{:24}  {:>10}  {:>8}", "Syscall", "Conteo", "%");
    println!("{:-<24}  {:-<10}  {:-<8}", "", "", "");
    let total_f = total as f64;
    for (scno, c) in v {
        let name = syscall_name(scno);
        let pct = if total > 0 { (c as f64) * 100.0 / total_f } else { 0.0 };
        println!("{:24}  {:>10}  {:>7.2}", name, c, pct);
    }
    println!("Total syscalls observadas: {}", total);
}
