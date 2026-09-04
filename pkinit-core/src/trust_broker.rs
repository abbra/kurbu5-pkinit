//! Transport-agnostic seam for consulting an external trust broker about a
//! KDC's presented CA bundle (trust-on-first-use). The concrete transport
//! (varlink over a Unix socket) lives in the krb5 plugin crate; `pkinit-core`
//! only defines the request/decision types and the synchronous trait so the
//! validation logic stays testable with a mock.

use crate::error::PkinitError;

/// A request to decide whether the KDC's presented CA bundle should be trusted.
pub struct KdcTrustRequest<'a> {
    /// Kerberos realm the exchange is for (e.g. `EXAMPLE.COM`).
    pub realm: &'a str,
    /// The KDC principal being authenticated (e.g. `krbtgt/EXAMPLE.COM@EXAMPLE.COM`).
    pub kdc_principal: &'a str,
    /// The KDC leaf (signer) certificate, DER-encoded.
    pub signer_cert_der: &'a [u8],
    /// The certificate chain presented in the reply's CMS SignedData, DER-encoded.
    pub presented_certs_der: &'a [Vec<u8>],
    /// True only for the anonymous exchange, which alone may establish new trust.
    pub interactive: bool,
}

/// The broker's decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdcTrustDecision {
    /// Trust the exchange; validate the chain against these anchor DERs.
    Trusted { anchors: Vec<Vec<u8>> },
    /// Explicitly refused (e.g. user declined, or the CA changed for a known realm).
    Denied(String),
    /// No decision available (unknown KDC on a non-interactive query).
    Unknown,
}

/// Synchronous trait the client calls when local chain validation fails and
/// trust-on-first-use is enabled. Implementations may block (the plugin's
/// implementation does a blocking varlink round-trip).
pub trait KdcCaTrustBroker {
    fn request_trust(
        &self,
        req: &KdcTrustRequest<'_>,
    ) -> Result<KdcTrustDecision, PkinitError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubBroker(KdcTrustDecision);
    impl KdcCaTrustBroker for StubBroker {
        fn request_trust(
            &self,
            _req: &KdcTrustRequest<'_>,
        ) -> Result<KdcTrustDecision, crate::error::PkinitError> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn broker_trait_is_object_safe_and_returns_decision() {
        let broker: Box<dyn KdcCaTrustBroker> = Box::new(StubBroker(KdcTrustDecision::Trusted {
            anchors: vec![vec![1, 2, 3]],
        }));
        let req = KdcTrustRequest {
            realm: "EXAMPLE.COM",
            kdc_principal: "krbtgt/EXAMPLE.COM@EXAMPLE.COM",
            signer_cert_der: &[0xAA],
            presented_certs_der: &[vec![0xBB]],
            interactive: true,
        };
        match broker.request_trust(&req).unwrap() {
            KdcTrustDecision::Trusted { anchors } => assert_eq!(anchors, vec![vec![1, 2, 3]]),
            other => panic!("expected Trusted, got {other:?}"),
        }
    }
}
