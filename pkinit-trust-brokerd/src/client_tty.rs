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

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use pkinit_trust_brokerd::store::{GRANT_PRESETS, GrantTtl, Prompter, TrustRequest};

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
    // O_NOCTTY: this process must never acquire someone else's terminal as
    // its own controlling tty — that could later deliver us a stray SIGHUP
    // (e.g. when that session's remote client disconnects) and take the
    // whole broker down with it.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open(tty)
        .ok()?;

    {
        let mut out = &file;
        writeln!(
            out,
            "PKINIT: KDC realm {} (principal {}) presents an unrecognized CA:",
            req.realm, req.kdc_principal
        )
        .ok()?;
        writeln!(out, "  Subject:    {}", req.ca_subject).ok()?;
        writeln!(out, "  SHA-256:    {}", req.fingerprint).ok()?;
        writeln!(out, "Trust this CA for {}?", req.realm).ok()?;
        for (i, (label, _)) in GRANT_PRESETS.iter().enumerate() {
            writeln!(out, "  {}) {label}", i + 1).ok()?;
        }
        writeln!(out, "  N) No, deny").ok()?;
        write!(out, "Choice: ").ok()?;
        out.flush().ok()?;
    }

    let mut line = String::new();
    BufReader::new(&file).read_line(&mut line).ok()?;
    let choice: usize = line.trim().parse().ok()?;
    GRANT_PRESETS
        .get(choice.checked_sub(1)?)
        .map(|(_, ttl)| *ttl)
}
