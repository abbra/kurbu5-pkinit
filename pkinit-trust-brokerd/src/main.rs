//! Reference PKINIT KDC-CA trust broker daemon: a varlink service over a Unix
//! socket that remembers per-realm CA pins and prompts on the tty for unknown
//! realms.
//!
//! Usage:
//!   pkinit-trust-brokerd [SOCKET] [--auto approve|deny] [--state FILE]
//!
//!   SOCKET            Unix socket path to bind (default:
//!                     $XDG_RUNTIME_DIR/pkinit-kdc-trust.sock).
//!   --auto approve    Non-interactively approve unknown realms (CI/testing).
//!   --auto deny       Non-interactively deny unknown realms (CI/testing).
//!   --state FILE      Persist pins to (and load them from) FILE.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use pkinit_trust_brokerd::Broker;
use pkinit_trust_brokerd::store::{AutoPrompter, PinStore, Prompter};
use pkinit_trust_proto::default_socket_path;
use zlink_smol::{Server, unix};

/// Terminal y/N prompter.
struct TtyPrompter;
impl Prompter for TtyPrompter {
    fn confirm(&self, realm: &str, subject: &str, fingerprint: &str) -> bool {
        eprintln!("PKINIT: KDC realm {realm} presents an unrecognized CA:");
        eprintln!("  Subject:    {subject}");
        eprintln!("  SHA-256:    {fingerprint}");
        eprint!("Trust this CA for {realm}? [y/N] ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line).is_err() {
            return false;
        }
        matches!(line.trim(), "y" | "Y" | "yes" | "YES")
    }
}

struct Args {
    socket: PathBuf,
    prompter: Box<dyn Prompter>,
    state: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut socket: Option<PathBuf> = None;
    let mut auto: Option<bool> = None;
    let mut state: Option<PathBuf> = None;

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
        None => Box::new(TtyPrompter),
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
