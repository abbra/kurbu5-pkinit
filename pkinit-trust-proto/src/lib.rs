//! Varlink interface `org.kurbu5.pkinit.KdcTrust`: the client (krb5 plugin)
//! asks the broker whether a KDC's presented CA bundle should be trusted.
//! Certificates travel as base64-encoded DER (varlink payloads are JSON text).

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub enum Decision {
    Trusted,
    Denied,
    Unknown,
}

/// Reply to `RequestTrust`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct TrustReply {
    pub decision: Decision,
    /// Base64 DER anchors to validate against; present iff `decision == Trusted`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anchors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One realm's currently active trust pin, as returned by
/// `ListTrustedRealms`. Excludes pins whose time-boxed grant has lapsed —
/// those are no longer trusted, so callers building permanent config from
/// this list never pick up a stale grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct TrustedRealm {
    pub realm: String,
    /// Base64 DER of the pinned CA certificate.
    pub ca_der: String,
    /// Lowercase hex SHA-256 of the CA DER.
    pub fingerprint: String,
    /// Unix time the grant lapses; absent if granted "forever".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

/// Reply to `ListTrustedRealms`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct TrustStoreReply {
    pub realms: Vec<TrustedRealm>,
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

    /// Snapshot of every realm the broker currently trusts (i.e. holds a
    /// live, unexpired pin for) — what a separate client uses to write out
    /// permanent `pkinit_anchors` configuration once a user has confirmed a
    /// CA through the usual TOFU prompt.
    async fn list_trusted_realms(
        &mut self,
    ) -> zlink::Result<Result<TrustStoreReply, KdcTrustError<'_>>>;
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

    #[test]
    fn trust_store_reply_round_trips() {
        let reply = TrustStoreReply {
            realms: vec![
                TrustedRealm {
                    realm: "EXAMPLE.COM".to_string(),
                    ca_der: "QUJD".to_string(),
                    fingerprint: "ab12".to_string(),
                    expires_at: Some(1_800_000_000),
                },
                TrustedRealm {
                    realm: "OTHER.EXAMPLE.COM".to_string(),
                    ca_der: "REVG".to_string(),
                    fingerprint: "cd34".to_string(),
                    expires_at: None,
                },
            ],
        };
        let json = serde_json::to_string(&reply).unwrap();
        assert!(!json.contains("\"expires_at\":null")); // None is skipped
        let back: TrustStoreReply = serde_json::from_str(&json).unwrap();
        assert_eq!(back, reply);
    }
}
