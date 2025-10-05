use nix::sched::{CloneFlags, clone};
use nix::sys::wait::waitpid;
use nix::unistd::{Gid, Uid, close, execvpe, pipe, read, setgid, sethostname, setuid, write};
use std::env;
use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::process::exit;

const STACK_SIZE: usize = 1024 * 1024; // 1 MB

fn child_main(pipe_read_fd: BorrowedFd, pipe_write_fd: RawFd, args: &[CString]) -> isize {
    println!("[CHILD] Process started");

    if let Err(_) = close(pipe_write_fd) {
        eprintln!("[CHILD:ERROR] Failed to close write end of pipe");
        return -1;
    }

    if let Err(e) = sethostname("confine-container") {
        eprintln!("[CHILD:ERROR] sethostname failed: {}", e);
        return -1;
    }

    println!("[CHILD] Waiting on parent to set up UID/GID maps...");
    let mut buf = [0u8; 1];
    if let Err(_) = read(pipe_read_fd, &mut buf) {
        eprintln!("[CHILD:ERROR] Failed to read from pipe");
        return -1;
    }
    println!("[CHILD] Signal received.");

    // by now, the maps are written, we play god (safely) in this namespace.
    if let Err(err) = setgid(Gid::from_raw(0)) {
        eprintln!("[CHILD:ERROR] setgid failed: {err}");
        return -1;
    }

    if let Err(err) = setuid(Uid::from_raw(0)) {
        eprintln!("[CHILD:ERROR] setuid failed: {err}");
        return -1;
    }

    // execvpe replaces the current process, so it will never return on success.
    match execvpe(&args[0], &args, &[] as &[CString]) {
        Err(err) => {
            eprintln!("[CHILD:ERROR] execvpe failed: {err}");
            return 1;
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

    let (pipe_read_fd, pipe_write_fd) = match pipe() {
        Ok(fds) => fds,
        Err(err) => {
            eprintln!("[PARENT:ERROR] Failed to create pipe: {err}");
            exit(1);
        }
    };

    // The entry point for the child process.
    let child_func =
        Box::new(|| child_main(pipe_read_fd.as_fd(), pipe_write_fd.as_raw_fd(), &c_args));
    let mut stack = [0u8; STACK_SIZE];
    let flags = CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWUSER;

    let child_pid = unsafe {
        match clone(
            child_func,
            &mut stack,
            flags,
            Some(nix::sys::signal::Signal::SIGCHLD as i32),
        ) {
            Ok(pid) => pid,
            Err(e) => {
                eprintln!("[PARENT:ERROR] clone failed: {}", e);
                exit(1);
            }
        }
    };

    println!("[PARENT] Cloned child process with PID {}", child_pid);

    if let Err(_) = close(pipe_read_fd) {
        eprintln!("[PARENT:ERROR] failed to close read end of pipe");
        exit(1);
    }

    let host_uid = Uid::current();
    let host_gid = Gid::current();

    println!("[PARENT] Setting up UID/GID maps for child...");

    let gid_map_path = format!("/proc/{}/gid_map", child_pid);
    let setgroups_path = format!("/proc/{}/setgroups", child_pid);

    if let Ok(mut file) = File::create(&setgroups_path) {
        if let Err(err) = file.write_all(b"deny") {
            eprintln!("[PARENT:ERROR] Failed to write to {setgroups_path}: {err}");
        }
    } else {
        eprintln!("[PARENT:ERROR] Failed to open {setgroups_path}");
    }

    let gid_map_content = format!("0 {} 1", host_gid);
    if let Ok(mut file) = File::create(&gid_map_path) {
        if let Err(err) = file.write_all(gid_map_content.as_bytes()) {
            eprintln!("[PARENT:ERROR] Failed to write to {gid_map_path}: {err}");
        }
    } else {
        eprintln!("[PARENT:ERROR] Failed to open {gid_map_path}");
    }

    let uid_map_path = format!("/proc/{}/uid_map", child_pid);
    let uid_map_content = format!("0 {} 1", host_uid);
    if let Ok(mut file) = File::create(&uid_map_path) {
        if let Err(err) = file.write_all(uid_map_content.as_bytes()) {
            eprintln!("[PARENT:ERROR] Failed to write to {uid_map_path}: {err}");
        }
    } else {
        eprintln!("[PARENT:ERROR] Failed to open {uid_map_path}");
    }

    // Signal to child
    println!("[PARENT] Signaling child to continue.");
    if let Err(_) = write(pipe_write_fd.as_fd(), &[0]) {
        eprintln!("PARENT:ERROR] Failed to write to pipe");
    }

    if let Err(_) = close(pipe_write_fd) {
        eprintln!("[PARENT:ERROR] Failed to close write end of pipe");
    }

    if let Err(err) = waitpid(child_pid, None) {
        eprintln!("[PARENT:ERROR] waitpid failed: {err}");
    }
}
