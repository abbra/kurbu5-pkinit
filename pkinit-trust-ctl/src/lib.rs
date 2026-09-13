//! Library backing the `pkinit-trust-ctl` binary: rendering the trust store
//! for humans and exporting it as permanent `pkinit_anchors` configuration.
//! Split out from `main.rs` (which owns argument parsing and the varlink
//! call) so both can be exercised in integration tests against a real
//! broker, without shelling out to the built binary.

use std::path::Path;

use base64::Engine;
use pkinit_trust_proto::TrustStoreReply;

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A rough "in 2d 3h 12m" (or "expired") rendering, without pulling in a
/// date/time crate for something this small.
pub fn format_expiry(expires_at: u64) -> String {
    let now = now_secs();
    if expires_at <= now {
        return "expired".to_string();
    }
    let remaining = expires_at - now;
    let days = remaining / 86400;
    let hours = (remaining % 86400) / 3600;
    let minutes = (remaining % 3600) / 60;
    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 || parts.is_empty() {
        parts.push(format!("{minutes}m"));
    }
    format!("in {}", parts.join(" "))
}

/// Human-readable rendering of the trust store, as printed by `list`.
pub fn render_list(store: &TrustStoreReply) -> String {
    if store.realms.is_empty() {
        return "(no realms currently trusted)\n".to_string();
    }
    let mut out = format!("{:<30} {:<64} EXPIRES\n", "REALM", "FINGERPRINT (SHA-256)");
    for r in &store.realms {
        let expires = r.expires_at.map_or("never".to_string(), format_expiry);
        out.push_str(&format!(
            "{:<30} {:<64} {expires}\n",
            r.realm, r.fingerprint
        ));
    }
    out
}

/// Realm names are conventionally uppercase DNS-like or X.500-like strings;
/// reject anything else rather than build a file path out of it.
pub fn safe_filename(realm: &str) -> Option<&str> {
    let ok = !realm.is_empty()
        && realm != "."
        && realm != ".."
        && realm
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    ok.then_some(realm)
}

pub fn to_pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 output is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// Write each trusted realm's CA as `anchors_dir/<realm>.pem` and build the
/// matching `[realms]` `pkinit_anchors` snippet. Returns the snippet text;
/// the caller decides whether that goes to a file or stdout — nothing here
/// ever touches an existing krb5.conf.
pub fn export(store: &TrustStoreReply, anchors_dir: &Path) -> std::io::Result<String> {
    std::fs::create_dir_all(anchors_dir)?;

    let mut snippet = String::from("[realms]\n");
    for r in &store.realms {
        let Some(filename) = safe_filename(&r.realm) else {
            eprintln!("pkinit-trust-ctl: skipping realm: not a safe filename");
            continue;
        };
        let der = base64::engine::general_purpose::STANDARD
            .decode(&r.ca_der)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let cert_path = anchors_dir.join(format!("{filename}.pem"));
        std::fs::write(&cert_path, to_pem(&der))?;
        eprintln!("wrote {}", cert_path.display());

        snippet.push_str(&format!(" {} = {{\n", r.realm));
        snippet.push_str(&format!(
            "  pkinit_anchors = FILE:{}\n",
            cert_path.display()
        ));
        snippet.push_str(" }\n");
    }
    Ok(snippet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_filename_accepts_typical_realms() {
        assert_eq!(safe_filename("EXAMPLE.COM"), Some("EXAMPLE.COM"));
        assert_eq!(
            safe_filename("sub.example-corp.com"),
            Some("sub.example-corp.com")
        );
    }

    #[test]
    fn safe_filename_rejects_path_traversal() {
        assert_eq!(safe_filename(".."), None);
        assert_eq!(safe_filename("."), None);
        assert_eq!(safe_filename("../../etc/passwd"), None);
        assert_eq!(safe_filename("a/b"), None);
        assert_eq!(safe_filename(""), None);
    }

    #[test]
    fn pem_round_trips_through_base64() {
        let der = b"not a real certificate, just bytes to wrap";
        let pem = to_pem(der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap();
        assert_eq!(decoded, der);
    }

    #[test]
    fn format_expiry_reports_expired_for_the_past() {
        assert_eq!(format_expiry(1), "expired");
    }

    #[test]
    fn format_expiry_reports_a_future_duration() {
        let soon = now_secs() + 3661; // 1h 1m 1s out
        let s = format_expiry(soon);
        assert!(s.starts_with("in "));
        assert!(s.contains('h'));
    }

    #[test]
    fn render_list_reports_no_realms() {
        let store = TrustStoreReply { realms: vec![] };
        assert_eq!(render_list(&store), "(no realms currently trusted)\n");
    }

    #[test]
    fn export_skips_unsafe_realm_names() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStoreReply {
            realms: vec![pkinit_trust_proto::TrustedRealm {
                realm: "../evil".to_string(),
                ca_der: base64::engine::general_purpose::STANDARD.encode(b"x"),
                fingerprint: "fp".to_string(),
                expires_at: None,
            }],
        };
        let snippet = export(&store, dir.path()).unwrap();
        assert_eq!(snippet, "[realms]\n");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
