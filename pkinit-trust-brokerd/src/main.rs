//! Reference PKINIT KDC-CA trust broker daemon: a varlink service over a Unix
//! socket that remembers per-realm CA pins and prompts for unknown realms.
//!
//! Usage:
//!   pkinit-trust-brokerd [SOCKET] [--auto approve|deny] [--state FILE] [--ui auto|gui|tty]
//!
//!   SOCKET            Unix socket path to bind (default:
//!                     $XDG_RUNTIME_DIR/pkinit-kdc-trust.sock).
//!   --auto approve    Non-interactively approve unknown realms (CI/testing).
//!   --auto deny       Non-interactively deny unknown realms (CI/testing).
//!   --state FILE      Persist pins to (and load them from) FILE.
//!   --ui auto|gui|tty Prompting UI when a decision is needed (default: auto).
//!                     "gui" shows a desktop notification with a button per
//!                     grant duration (see `graphical`); "tty" always prompts
//!                     on the terminal; "auto" uses the notification UI when
//!                     a graphical session is detected ($DISPLAY or
//!                     $WAYLAND_DISPLAY set) and falls back to the terminal
//!                     otherwise, or if the notification daemon can't help.
//!                     Ignored when --auto is given.

mod graphical;

use std::io::{BufRead, Write};
use std::path::PathBuf;

use graphical::NotifyPrompter;
use pkinit_trust_brokerd::Broker;
use pkinit_trust_brokerd::store::{
    AutoPrompter, GRANT_PRESETS, GrantTtl, PinStore, Prompter, TrustRequest,
};
use pkinit_trust_proto::default_socket_path;
use zlink_smol::{Server, unix};

/// Terminal prompter: shows the request and a numbered menu of grant
/// durations. Any unrecognized input (including a bare "no" or empty line)
/// denies, so the fail-closed default doesn't depend on parsing a "yes".
struct TtyPrompter;
impl Prompter for TtyPrompter {
    fn confirm(&self, req: &TrustRequest<'_>) -> Option<GrantTtl> {
        eprintln!(
            "PKINIT: KDC realm {} (principal {}) presents an unrecognized CA:",
            req.realm, req.kdc_principal
        );
        eprintln!("  Subject:    {}", req.ca_subject);
        eprintln!("  SHA-256:    {}", req.fingerprint);
        eprintln!("Trust this CA for {}?", req.realm);
        for (i, (label, _)) in GRANT_PRESETS.iter().enumerate() {
            eprintln!("  {}) {label}", i + 1);
        }
        eprintln!("  N) No, deny");
        eprint!("Choice: ");
        let _ = std::io::stderr().flush();

        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line).is_err() {
            return None;
        }
        let choice: usize = line.trim().parse().ok()?;
        GRANT_PRESETS
            .get(choice.checked_sub(1)?)
            .map(|(_, ttl)| *ttl)
    }
}

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
/// still falls back to the terminal if this is wrong (e.g. no notification
/// daemon actually running, or a headless X server).
fn graphical_session_hint() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some()
}

fn prompter_for(ui: UiMode) -> Box<dyn Prompter> {
    let notify = || {
        Box::new(NotifyPrompter {
            fallback: Box::new(TtyPrompter),
        }) as Box<dyn Prompter>
    };
    match ui {
        UiMode::Tty => Box::new(TtyPrompter),
        UiMode::Gui => notify(),
        UiMode::Auto if graphical_session_hint() => notify(),
        UiMode::Auto => Box::new(TtyPrompter),
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
    let _ = std::fs::remove_file(&path);
    smol::block_on(async {
        let listener = unix::bind(&path)?;
        let broker = Broker::new(store, args.prompter);
        let server = Server::new(listener, broker);
        eprintln!("pkinit-trust-brokerd listening on {}", path.display());
        server.run().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
