//! Boots the real `Broker` service on a temp socket and drives it with the
//! proxy client from `pkinit-trust-proto`.

use base64::Engine;
use pkinit_core::test_support::build_kdc_chain;
use pkinit_trust_brokerd::Broker;
use pkinit_trust_brokerd::store::{GrantTtl, PinStore, Prompter, TrustRequest};
use pkinit_trust_proto::{Decision, KdcTrustProxy};
use zlink_smol::{Server, unix};

struct AlwaysYes;
impl Prompter for AlwaysYes {
    fn confirm(&self, _req: &TrustRequest<'_>) -> Option<GrantTtl> {
        Some(GrantTtl::Forever)
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[test]
fn interactive_pins_then_noninteractive_trusts() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("t.sock");
    let sock_client = sock.clone();
    let chain = build_kdc_chain("R");

    smol::block_on(async move {
        let listener = unix::bind(&sock).unwrap();
        let broker = Broker::new(PinStore::in_memory(), Box::new(AlwaysYes));
        let server = Server::new(listener, broker);

        let client = async move {
            let mut conn = unix::connect(&sock_client).await.unwrap();
            let ca_b64 = b64(&chain.ca_der);
            let leaf_b64 = b64(&chain.kdc_leaf_der);

            let r1 = conn
                .request_trust("R", "krbtgt/R@R", &leaf_b64, vec![ca_b64.clone()], true)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(r1.decision, Decision::Trusted);

            let r2 = conn
                .request_trust("R", "krbtgt/R@R", &leaf_b64, vec![ca_b64.clone()], false)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(r2.decision, Decision::Trusted);

            let store = conn.list_trusted_realms().await.unwrap().unwrap();
            assert_eq!(store.realms.len(), 1);
            assert_eq!(store.realms[0].realm, "R");
            assert_eq!(store.realms[0].ca_der, ca_b64);
            assert_eq!(store.realms[0].expires_at, None);
        };

        // Run server and client concurrently; return when the client is done.
        let _ = smol::future::or(
            async {
                if let Err(e) = server.run().await {
                    eprintln!("server error: {e:?}");
                }
            },
            client,
        )
        .await;
    });
}
