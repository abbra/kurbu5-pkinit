//! Varlink interface `org.kurbu5.pkinit.KdcTrust`: the client (krb5 plugin)
//! asks the broker whether a KDC's presented CA bundle should be trusted.
//! Certificates travel as base64-encoded DER (varlink payloads are JSON text).

// The zlink derive/attribute macros emit `::zlink` paths; alias the chosen
// runtime crate so that resolves without depending on the umbrella `zlink` crate.
extern crate zlink_smol as zlink;

use serde::{Deserialize, Serialize};
use zlink::{ReplyError, introspect, proxy};

/// Reverse-DNS varlink interface name.
pub const INTERFACE: &str = "org.kurbu5.pkinit.KdcTrust";
/// Conventional socket file name (joined with `$XDG_RUNTIME_DIR` by callers).
pub const DEFAULT_SOCKET_NAME: &str = "pkinit-kdc-trust.sock";
/// Default Unix socket path: `$XDG_RUNTIME_DIR`/`DEFAULT_SOCKET_NAME`, or
/// `/tmp`/`DEFAULT_SOCKET_NAME` when `XDG_RUNTIME_DIR` is unset. Shared by the
/// daemon (which binds it) and the client plugin (which connects to it) so
/// both sides agree on the default.
pub fn default_socket_path() -> std::path::PathBuf {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"));
    dir.join(DEFAULT_SOCKET_NAME)
}

/// The broker's decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Trusted,
    Denied,
    Unknown,
}

/// Reply to `RequestTrust`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustReply {
    pub decision: Decision,
    /// Base64 DER anchors to validate against; present iff `decision == Trusted`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anchors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Varlink errors the broker may return.
#[derive(Debug, PartialEq, ReplyError, introspect::ReplyError)]
#[zlink(interface = "org.kurbu5.pkinit.KdcTrust")]
pub enum KdcTrustError<'a> {
    InvalidRequest { reason: &'a str },
    Internal { reason: &'a str },
}

/// Client proxy. Certificates are base64-encoded DER.
#[proxy("org.kurbu5.pkinit.KdcTrust")]
pub trait KdcTrustProxy {
    async fn request_trust(
        &mut self,
        realm: &str,
        kdc_principal: &str,
        signer_cert: &str,
        presented_certs: Vec<String>,
        interactive: bool,
    ) -> zlink::Result<Result<TrustReply, KdcTrustError<'_>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_reply_round_trips_trusted() {
        let reply = TrustReply {
            decision: Decision::Trusted,
            anchors: vec!["QUJD".to_string()],
            reason: None,
        };
        let json = serde_json::to_string(&reply).unwrap();
        assert!(json.contains("\"Trusted\""));
        assert!(!json.contains("reason")); // None is skipped
        let back: TrustReply = serde_json::from_str(&json).unwrap();
        assert!(matches!(back.decision, Decision::Trusted));
        assert_eq!(back.anchors, vec!["QUJD".to_string()]);
        assert!(back.reason.is_none());
    }

    #[test]
    fn trust_reply_round_trips_denied_with_reason() {
        let reply = TrustReply {
            decision: Decision::Denied,
            anchors: vec![],
            reason: Some("user declined".to_string()),
        };
        let json = serde_json::to_string(&reply).unwrap();
        assert!(!json.contains("anchors")); // empty is skipped
        let back: TrustReply = serde_json::from_str(&json).unwrap();
        assert!(matches!(back.decision, Decision::Denied));
        assert_eq!(back.reason.as_deref(), Some("user declined"));
    }
}
