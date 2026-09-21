//! Reference PKINIT KDC-CA trust broker library: the varlink `Broker` service
//! and its pin store. The `pkinit-trust-brokerd` binary is a thin wrapper; the
//! service lives here so integration tests can drive it directly.

pub mod store;

use base64::Engine;
use pkinit_trust_proto::{KdcTrustError, TrustReply, TrustStoreReply};
use zlink::connection::socket::FetchPeerCredentials;
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
impl<Sock> Broker
where
    Sock::ReadHalf: FetchPeerCredentials,
{
    async fn request_trust(
        &mut self,
        realm: &str,
        kdc_principal: &str,
        signer_cert: &str,
        presented_certs: Vec<String>,
        interactive: bool,
        #[zlink(connection)] conn: &mut Connection<Sock>,
    ) -> Result<TrustReply, KdcTrustError<'_>> {
        // Trust is still keyed only on the realm; kdc_principal is passed
        // through to the prompter purely for display.
        let signer = base64::engine::general_purpose::STANDARD
            .decode(signer_cert)
            .map_err(|_| KdcTrustError::InvalidRequest {
                reason: "signer_cert not base64",
            })?;
        let presented = decode_all(&presented_certs).ok_or(KdcTrustError::InvalidRequest {
            reason: "presented_certs not base64",
        })?;

        // Best-effort: lets a prompter reach the connecting client's own
        // controlling terminal. `None` (unsupported platform, or the peer
        // already gone) just narrows which prompters can act.
        let client_pid = conn
            .peer_credentials()
            .await
            .ok()
            .map(|creds| creds.process_id().as_raw_pid());

        let reply = self.store.decide(
            realm,
            kdc_principal,
            client_pid,
            &signer,
            &presented,
            interactive,
            self.prompter.as_ref(),
        );
        eprintln!(
            "[broker] realm={} interactive={interactive} decision={:?}",
            store::sanitize_for_display(realm),
            reply.decision
        );
        Ok(reply)
    }

    /// Snapshot of every realm currently trusted, for a separate client to
    /// turn into permanent `pkinit_anchors` configuration.
    async fn list_trusted_realms(&mut self) -> Result<TrustStoreReply, KdcTrustError<'_>> {
        Ok(TrustStoreReply {
            realms: self.store.trusted_realms(),
        })
    }
}
