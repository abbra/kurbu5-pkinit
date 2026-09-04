//! Reference PKINIT KDC-CA trust broker library: the varlink `Broker` service
//! and its pin store. The `pkinit-trust-brokerd` binary is a thin wrapper; the
//! service lives here so integration tests can drive it directly.

// The zlink service/derive macros emit `::zlink` paths; alias the runtime crate.
extern crate zlink_smol as zlink;

pub mod store;

use base64::Engine;
use pkinit_trust_proto::{KdcTrustError, TrustReply};
use zlink::service;

use store::{PinStore, Prompter};

/// The varlink `org.kurbu5.pkinit.KdcTrust` service: a pin store plus a
/// prompter for interactive (unknown-realm) decisions.
pub struct Broker {
    store: PinStore,
    prompter: Box<dyn Prompter>,
}

impl Broker {
    pub fn new(store: PinStore, prompter: Box<dyn Prompter>) -> Self {
        Self { store, prompter }
    }
}

fn decode_all(items: &[String]) -> Option<Vec<Vec<u8>>> {
    let eng = base64::engine::general_purpose::STANDARD;
    items.iter().map(|s| eng.decode(s).ok()).collect()
}

#[service(interface = "org.kurbu5.pkinit.KdcTrust")]
impl Broker {
    async fn request_trust(
        &mut self,
        realm: &str,
        kdc_principal: &str,
        signer_cert: &str,
        presented_certs: Vec<String>,
        interactive: bool,
    ) -> Result<TrustReply, KdcTrustError<'_>> {
        // kdc_principal is in the wire interface but the reference policy
        // keys only on the realm.
        let _ = kdc_principal;
        let signer = base64::engine::general_purpose::STANDARD
            .decode(signer_cert)
            .map_err(|_| KdcTrustError::InvalidRequest {
                reason: "signer_cert not base64",
            })?;
        let presented = decode_all(&presented_certs).ok_or(KdcTrustError::InvalidRequest {
            reason: "presented_certs not base64",
        })?;

        let subject = format!("(CA for {realm})");
        Ok(self.store.decide(
            realm,
            &subject,
            &signer,
            &presented,
            interactive,
            self.prompter.as_ref(),
        ))
    }
}
