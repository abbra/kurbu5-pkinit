//! Reference PKINIT KDC-CA trust broker daemon: a varlink service over a Unix
//! socket that remembers per-realm CA pins and prompts for unknown realms.
//!
//! Usage:
//!   pkinit-trust-brokerd [SOCKET] [--auto approve|deny] [--state FILE] [--ui auto|gui|tty]
//!
//!   SOCKET            Unix socket path to bind (default:
//!                     $XDG_RUNTIME_DIR/pkinit-kdc-trust.sock). Ignored under
//!                     systemd socket activation (see below), which supplies
//!                     an already-bound, already-listening socket instead.
//!   --auto approve    Non-interactively approve unknown realms (CI/testing).
//!   --auto deny       Non-interactively deny unknown realms (CI/testing).
//!   --state FILE      Persist pins to (and load them from) FILE.
//!   --ui auto|gui|tty Prompting UI when a decision is needed (default: auto).
//!                     "gui" shows a desktop notification with buttons for "1hr" and "trust always"
//!                     grant durations (see `graphical`); "tty" prompts on the *connecting
//!                     client's* controlling terminal, found via its PID from `SO_PEERCRED` (see
//!                     `client_tty`) — this is what makes a plain console `kinit`, a root shell, or
//!                     an SSH session work with no graphical session at all. "auto" uses the
//!                     notification UI when a graphical session is detected ($DISPLAY or
//!                     $WAYLAND_DISPLAY set) and the client's terminal otherwise, or if the
//!                     notification daemon can't help. Either way, if nothing usable is found, the
//!                     request is denied (fail closed) rather than left unanswered. Ignored when
//!                     --auto is given.
//!
//! Autoactivation: when started with `LISTEN_PID`/`LISTEN_FDS` set (i.e. by
//! systemd socket activation, per sd_listen_fds(3)), the daemon uses the
//! socket systemd already bound and is listening on instead of binding
//! SOCKET itself. See `contrib/systemd/` for reference unit files that wire
//! this up as an on-demand per-user service.

mod client_tty;
mod graphical;

use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use client_tty::ClientTtyPrompter;
use graphical::NotifyPrompter;
use pkinit_trust_brokerd::Broker;
use pkinit_trust_brokerd::store::{AutoPrompter, PinStore, Prompter};
use pkinit_trust_proto::default_socket_path;
use zlink_smol::{Server, unix};

#[derive(Clone, Copy)]
enum UiMode {
    Auto,
    Gui,
    Tty,
}

struct Args {
    socket: PathBuf,
    prompter: Box<dyn Prompter>,
    state: Option<PathBuf>,
}

/// Hints that a graphical session is likely available, so it's worth trying
/// the notification UI at all. Not authoritative — the notification prompter
/// still falls back to the client's terminal if this is wrong (e.g. no
/// notification daemon actually running, or a headless X server).
fn graphical_session_hint() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some()
}

/// First fd systemd passes on socket activation, per sd_listen_fds(3).
const SD_LISTEN_FDS_START: RawFd = 3;

/// If we were started via systemd socket activation, take ownership of the
/// socket it already bound and is listening on. Returns `None` (so the
/// caller binds SOCKET itself) when `LISTEN_PID` is absent, malformed, or
/// names a different process — the last case matters because these env vars
/// are inherited across `exec`, so a process socket-activated once must not
/// have a child mistake stale values for its own activation.
fn systemd_activation_fd() -> Option<OwnedFd> {
    let listen_pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    if listen_pid != std::process::id() {
        return None;
    }
    let listen_fds: usize = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    if listen_fds == 0 {
        return None;
    }
    if listen_fds > 1 {
        eprintln!(
            "pkinit-trust-brokerd: warning: systemd passed {listen_fds} sockets, expected 1; using the first"
        );
    }
    // SAFETY: LISTEN_PID matching our own pid means systemd opened
    // SD_LISTEN_FDS_START for this exact process and hands us ownership.
    Some(unsafe { OwnedFd::from_raw_fd(SD_LISTEN_FDS_START) })
}

fn prompter_for(ui: UiMode) -> Box<dyn Prompter> {
    let notify = || {
        Box::new(NotifyPrompter {
            fallback: Box::new(ClientTtyPrompter),
        }) as Box<dyn Prompter>
    };
    match ui {
        UiMode::Tty => Box::new(ClientTtyPrompter),
        UiMode::Gui => notify(),
        UiMode::Auto if graphical_session_hint() => notify(),
        UiMode::Auto => Box::new(ClientTtyPrompter),
    }
}

fn parse_args() -> Result<Args, String> {
    let mut socket: Option<PathBuf> = None;
    let mut auto: Option<bool> = None;
    let mut state: Option<PathBuf> = None;
    let mut ui: Option<UiMode> = None;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--auto" => {
                let v = it.next().ok_or("--auto requires approve|deny")?;
                auto = Some(match v.as_str() {
                    "approve" => true,
                    "deny" => false,
                    other => return Err(format!("--auto expects approve|deny, got {other}")),
                });
            }
            "--state" => {
                let v = it.next().ok_or("--state requires a file path")?;
                state = Some(PathBuf::from(v));
            }
            "--ui" => {
                let v = it.next().ok_or("--ui requires auto|gui|tty")?;
                ui = Some(match v.as_str() {
                    "auto" => UiMode::Auto,
                    "gui" => UiMode::Gui,
                    "tty" => UiMode::Tty,
                    other => return Err(format!("--ui expects auto|gui|tty, got {other}")),
                });
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown option: {other}"));
            }
            other => {
                if socket.is_some() {
                    return Err(format!("unexpected extra argument: {other}"));
                }
                socket = Some(PathBuf::from(other));
            }
        }
    }

    let prompter: Box<dyn Prompter> = match auto {
        Some(approve) => Box::new(AutoPrompter { approve }),
        None => prompter_for(ui.unwrap_or(UiMode::Auto)),
    };

    Ok(Args {
        socket: socket.unwrap_or_else(default_socket_path),
        prompter,
        state,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("pkinit-trust-brokerd: {e}");
            std::process::exit(2);
        }
    };

    let store = match args.state {
        Some(path) => PinStore::open(path)?,
        None => PinStore::in_memory(),
    };

    let path = args.socket;
    smol::block_on(async {
        let (listener, via) = match systemd_activation_fd() {
            Some(fd) => (unix::Listener::try_from(fd)?, "systemd socket activation"),
            None => {
                let _ = std::fs::remove_file(&path);
                (unix::bind(&path)?, "direct bind")
            }
        };
        let broker = Broker::new(store, args.prompter);
        let server = Server::new(listener, broker);
        eprintln!(
            "pkinit-trust-brokerd listening on {} ({via})",
            path.display()
        );
        server.run().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
