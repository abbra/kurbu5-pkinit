//! Client-terminal prompter: instead of the broker's own terminal (it may
//! not have one — see autoactivation in `main`) or a desktop notification,
//! prompt directly on the controlling terminal of the process that placed
//! the varlink call. This is what makes TOFU consent work for `kinit` run at
//! a plain console, over SSH, or in a root shell, with no graphical session
//! anywhere in the picture: the client and the broker are both on the same
//! host (the broker only ever listens on a local Unix socket), so the
//! client's tty is always a real, locally-openable device.
//!
//! Finding that terminal: `SO_PEERCRED` (surfaced as `TrustRequest::client_pid`
//! by `lib.rs`) gives the connecting process's PID, and `/proc/<pid>/fd/{0,2,1}`
//! are checked in turn for the first one that's a tty device — stdin first
//! (the conventional place to answer a prompt), then stderr and stdout as
//! fallbacks for a client that redirected stdin but is still attached to a
//! terminal otherwise.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use pkinit_trust_brokerd::store::{
    GRANT_PRESETS, GrantTtl, PROMPT_TIMEOUT, Prompter, TrustRequest,
};

pub struct ClientTtyPrompter;

impl Prompter for ClientTtyPrompter {
    fn confirm(&self, req: &TrustRequest<'_>) -> Option<GrantTtl> {
        let Some(pid) = req.client_pid else {
            eprintln!(
                "[broker] client PID unavailable (no peer credentials); can't reach a terminal, denying"
            );
            return None;
        };
        let Some(tty) = client_tty_path(pid) else {
            eprintln!(
                "[broker] client (pid {pid}) has no open tty on stdin/stderr/stdout; denying"
            );
            return None;
        };
        match prompt_on(&tty, req) {
            Some(grant) => Some(grant),
            None => {
                eprintln!(
                    "[broker] prompting on {} failed or was declined",
                    tty.display()
                );
                None
            }
        }
    }
}

/// The first of the client's stdin/stderr/stdout that's a tty device, if any.
fn client_tty_path(pid: i32) -> Option<PathBuf> {
    [0, 2, 1].into_iter().find_map(|fd| {
        let target = std::fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()?;
        let is_tty =
            target.file_name()?.to_str()?.starts_with("tty") || target.to_str()?.contains("/pts/");
        is_tty.then_some(target)
    })
}

fn prompt_on(tty: &Path, req: &TrustRequest<'_>) -> Option<GrantTtl> {
    let deadline = std::time::Instant::now() + PROMPT_TIMEOUT;

    // O_NOCTTY: this process must never acquire someone else's terminal as
    // its own controlling tty — that could later deliver us a stray SIGHUP
    // (e.g. when that session's remote client disconnects) and take the
    // whole broker down with it.
    // O_NONBLOCK: without it, `open()` itself and every read/write below
    // can block past `deadline` (e.g. a stalled tty from XOFF, or a client
    // that writes a partial line with no trailing newline).
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
        .open(tty)
        .ok()?;

    let mut prompt = String::new();
    writeln!(
        prompt,
        "PKINIT: KDC realm {} (principal {}) presents an unrecognized CA:",
        req.realm, req.kdc_principal
    )
    .ok()?;
    writeln!(prompt, "  Subject:    {}", req.ca_subject).ok()?;
    writeln!(prompt, "  SHA-256:    {}", req.fingerprint).ok()?;
    writeln!(prompt, "Trust this CA for {}?", req.realm).ok()?;
    for (i, (label, _)) in GRANT_PRESETS.iter().enumerate() {
        writeln!(prompt, "  {}) {label}", i + 1).ok()?;
    }
    writeln!(prompt, "  N) No, deny").ok()?;
    write!(prompt, "Choice: ").ok()?;

    if !write_all_deadline(&file, prompt.as_bytes(), deadline) {
        return None;
    }

    let line = read_line_deadline(&file, deadline)?;
    let choice: usize = line.trim().parse().ok()?;
    GRANT_PRESETS
        .get(choice.checked_sub(1)?)
        .map(|(_, ttl)| *ttl)
}

/// Writes all of `buf` to `file`, polling for `POLLOUT` before each write so
/// a stalled tty can't hang the syscall past `deadline`. `file` must be
/// `O_NONBLOCK`. Returns `false` on timeout or write error.
fn write_all_deadline(file: &std::fs::File, mut buf: &[u8], deadline: std::time::Instant) -> bool {
    let mut out = file;
    while !buf.is_empty() {
        if !poll_fd(file, libc::POLLOUT, deadline) {
            return false;
        }
        match out.write(buf) {
            Ok(0) => return false,
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return false,
        }
    }
    true
}

/// Reads a single newline-terminated line from `file` (the trailing `\n`
/// consumed but not included), polling for `POLLIN` before each read so a
/// client that sends a partial line can't hang the syscall past `deadline`.
/// `file` must be `O_NONBLOCK`. `None` on timeout, EOF, read error, or
/// invalid UTF-8.
fn read_line_deadline(file: &std::fs::File, deadline: std::time::Instant) -> Option<String> {
    let mut input = file;
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if !poll_fd(file, libc::POLLIN, deadline) {
            return None;
        }
        match input.read(&mut byte) {
            Ok(0) => return None,
            Ok(_) => {
                if byte[0] == b'\n' {
                    return String::from_utf8(buf).ok();
                }
                buf.push(byte[0]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
}

/// Waits until `file` signals `events` (e.g. `libc::POLLIN` or
/// `libc::POLLOUT`), or `deadline` elapses, so an unanswered prompt fails
/// closed instead of blocking the thread forever. `true` means the fd is
/// ready; `false` covers both a timeout and a poll error.
fn poll_fd(file: &std::fs::File, events: libc::c_short, deadline: std::time::Instant) -> bool {
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        let mut fds = [libc::pollfd {
            fd: file.as_raw_fd(),
            events,
            revents: 0,
        }];
        let ms = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 1, ms) };
        match ret {
            0 => return false,
            n if n > 0 => return fds[0].revents & events != 0,
            _ if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => {
                continue;
            }
            _ => return false,
        }
    }
}
