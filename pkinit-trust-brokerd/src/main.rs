//! Reference PKINIT KDC-CA trust broker daemon: a varlink service over a Unix
//! socket that remembers per-realm CA pins and prompts on the tty for unknown
//! realms.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use pkinit_trust_brokerd::store::{PinStore, Prompter};
use pkinit_trust_brokerd::Broker;
use pkinit_trust_proto::DEFAULT_SOCKET_NAME;
use zlink_smol::{unix, Server};

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

fn socket_path() -> PathBuf {
    if let Some(arg) = std::env::args().nth(1) {
        return PathBuf::from(arg);
    }
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    dir.join(DEFAULT_SOCKET_NAME)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = socket_path();
    let _ = std::fs::remove_file(&path);
    smol::block_on(async {
        let listener = unix::bind(&path)?;
        let broker = Broker::new(PinStore::in_memory(), Box::new(TtyPrompter));
        let server = Server::new(listener, broker);
        eprintln!("pkinit-trust-brokerd listening on {}", path.display());
        server.run().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
