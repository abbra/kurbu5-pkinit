//! Reference client for `pkinit-trust-brokerd`: a separate program (not the
//! krb5 plugin) that queries the broker's current trust store over varlink
//! and either prints it or turns it into permanent MIT Kerberos
//! configuration.
//!
//! The broker's TOFU pins are inherently soft state: session-scoped grants
//! expire, and even a "forever" pin lives only as long as the broker's state
//! file. Once a user has confirmed a CA through the usual prompt, `export`
//! lets an operator promote that decision to a permanent `pkinit_anchors`
//! entry in `krb5.conf` — so the broker is no longer in the loop for that
//! realm at all.
//!
//! Usage:
//!   pkinit-trust-ctl [--socket PATH] list
//!   pkinit-trust-ctl [--socket PATH] export --anchors-dir DIR [--conf-snippet FILE]
//!
//!   --socket PATH        Broker socket to connect to (default: same as
//!                        pkinit-trust-brokerd's own default).
//!   list                 Print the realms the broker currently trusts.
//!   export               Write each trusted realm's CA as
//!                        DIR/<realm>.pem and a matching `[realms]`
//!                        pkinit_anchors snippet (to --conf-snippet FILE, or
//!                        stdout if omitted). Nothing is written into an
//!                        existing krb5.conf directly — paste the snippet
//!                        in by hand, or point --conf-snippet at a file
//!                        pulled in via krb5.conf's `includedir`.

use std::path::PathBuf;

use pkinit_trust_ctl::{export, render_list};
use pkinit_trust_proto::{KdcTrustProxy, default_socket_path};

enum Command {
    List,
    Export {
        anchors_dir: PathBuf,
        conf_snippet: Option<PathBuf>,
    },
}

struct Args {
    socket: PathBuf,
    command: Command,
}

fn parse_args() -> Result<Args, String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();

    let mut socket = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--socket" {
            args.remove(i);
            if i >= args.len() {
                return Err("--socket requires a path".into());
            }
            socket = Some(PathBuf::from(args.remove(i)));
        } else {
            i += 1;
        }
    }

    let command = match args.first().map(String::as_str) {
        Some("list") => {
            if args.len() > 1 {
                return Err(format!("unexpected argument: {}", args[1]));
            }
            Command::List
        }
        Some("export") => {
            let mut anchors_dir = None;
            let mut conf_snippet = None;
            let mut rest = args[1..].iter();
            while let Some(a) = rest.next() {
                match a.as_str() {
                    "--anchors-dir" => {
                        let v = rest.next().ok_or("--anchors-dir requires a path")?;
                        anchors_dir = Some(PathBuf::from(v));
                    }
                    "--conf-snippet" => {
                        let v = rest.next().ok_or("--conf-snippet requires a path")?;
                        conf_snippet = Some(PathBuf::from(v));
                    }
                    other => return Err(format!("unknown option: {other}")),
                }
            }
            Command::Export {
                anchors_dir: anchors_dir.ok_or("export requires --anchors-dir DIR")?,
                conf_snippet,
            }
        }
        Some(other) => return Err(format!("unknown command: {other}")),
        None => return Err("usage: pkinit-trust-ctl [--socket PATH] <list|export>".into()),
    };

    Ok(Args {
        socket: socket.unwrap_or_else(default_socket_path),
        command,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("pkinit-trust-ctl: {e}");
            std::process::exit(2);
        }
    };

    smol::block_on(async {
        let mut conn = zlink_smol::unix::connect(&args.socket)
            .await
            .map_err(|e| format!("connecting to {}: {e}", args.socket.display()))?;
        let store = conn
            .list_trusted_realms()
            .await
            .map_err(|e| format!("varlink call failed: {e}"))?
            .map_err(|e| format!("broker returned an error: {e:?}"))?;

        match args.command {
            Command::List => print!("{}", render_list(&store)),
            Command::Export {
                anchors_dir,
                conf_snippet,
            } => {
                let snippet = export(&store, &anchors_dir)?;
                match conf_snippet {
                    Some(path) => {
                        std::fs::write(&path, &snippet)?;
                        eprintln!("wrote {}", path.display());
                    }
                    None => print!("{snippet}"),
                }
            }
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
