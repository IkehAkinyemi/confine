use nix::sched::{CloneFlags, clone};
use nix::sys::wait::waitpid;
use nix::unistd::{execvpe, sethostname};
use std::env;
use std::ffi::CString;
use std::process::exit;

const STACK_SIZE: usize = 1024 * 1024; // 1 MB

fn child_main(args: &[CString]) -> isize {
    println!("--- Child process started ---");

    if let Err(e) = sethostname("confine-container") {
        eprintln!("[ERROR] sethostname failed: {}", e);
        return -1;
    }

    // execvpe replaces the current process, so it will never return on success.
    match execvpe(&args[0], &args, &[] as &[CString]) {
        Err(err) => {
            eprintln!("[ERROR] Child process: execvpe failed with error: {err}");
            return 1
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <command> [args...]", args[0]);
        exit(1);
    }

    // Convert string arguments to C-style strings for the execvpe call.
    let c_args: Vec<CString> = args[1..]
        .iter()
        .map(|arg| CString::new(arg.as_bytes()).unwrap())
        .collect();

    let mut stack = [0u8; STACK_SIZE];
    let flags = CloneFlags::CLONE_NEWUTS;

    // The entry point for the child process.
    let child_func = Box::new(|| child_main(&c_args));

    let child_pid = unsafe {
        match clone(
            child_func,
            &mut stack,
            flags,
            Some(nix::sys::signal::Signal::SIGCHLD as i32),
        ) {
            Ok(pid) => pid,
            Err(e) => {
                eprintln!("[ERROR] clone failed: {}", e);
                exit(1);
            }
        }
    };

    println!("Cloned child process with PID {}", child_pid);

    if let Err(e) = waitpid(child_pid, None) {
        eprintln!("[ERROR] waitpid failed: {}", e);
    }
}
