//! Boots the real `Broker` service (mirroring
//! `pkinit-trust-brokerd/tests/roundtrip.rs`), pins one realm, then drives
//! `pkinit_trust_ctl::export` against the real `ListTrustedRealms` reply —
//! proving the exported PEM and krb5.conf snippet match what was actually
//! pinned, not just what a hand-built `TrustStoreReply` would look like.

use base64::Engine;
use pkinit_core::test_support::{build_kdc_chain, build_pq_kdc_chain};
use pkinit_trust_brokerd::Broker;
use pkinit_trust_brokerd::store::{GrantTtl, PinStore, Prompter, TrustRequest};
use pkinit_trust_proto::KdcTrustProxy;
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
fn export_writes_pem_and_snippet_for_a_trusted_realm() {
    let sock_dir = tempfile::tempdir().unwrap();
    let sock = sock_dir.path().join("t.sock");
    let sock_client = sock.clone();
    let chain = build_kdc_chain("R");
    let anchors_dir = tempfile::tempdir().unwrap();
    let anchors_path = anchors_dir.path().to_path_buf();

    smol::block_on(async move {
        let listener = unix::bind(&sock).unwrap();
        let broker = Broker::new(PinStore::in_memory(), Box::new(AlwaysYes));
        let server = Server::new(listener, broker);

        let client = async move {
            let mut conn = unix::connect(&sock_client).await.unwrap();
            let ca_b64 = b64(&chain.ca_der);
            let leaf_b64 = b64(&chain.kdc_leaf_der);
            conn.request_trust("R", "krbtgt/R@R", &leaf_b64, vec![ca_b64], true)
                .await
                .unwrap()
                .unwrap();

            let store = conn.list_trusted_realms().await.unwrap().unwrap();
            let snippet = pkinit_trust_ctl::export(&store, &anchors_path).unwrap();

            assert!(snippet.contains("[realms]"));
            assert!(snippet.contains(" R = {"));
            let cert_path = anchors_path.join("R.pem");
            assert!(snippet.contains(&format!("pkinit_anchors = FILE:{}", cert_path.display())));

            let pem = std::fs::read_to_string(&cert_path).unwrap();
            assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
            let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(body)
                .unwrap();
            assert_eq!(decoded, chain.ca_der);
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

/// Same as `export_writes_pem_and_snippet_for_a_trusted_realm`, but the
/// pinned CA is ML-DSA-65 (post-quantum) — `export` only base64-decodes and
/// PEM-wraps the anchor bytes, so it must round-trip identically regardless
/// of the certificate's signature algorithm.
#[test]
fn export_writes_pem_for_a_post_quantum_ca() {
    let sock_dir = tempfile::tempdir().unwrap();
    let sock = sock_dir.path().join("t.sock");
    let sock_client = sock.clone();
    let chain = build_pq_kdc_chain("PQ.EXAMPLE.COM");
    let anchors_dir = tempfile::tempdir().unwrap();
    let anchors_path = anchors_dir.path().to_path_buf();

    smol::block_on(async move {
        let listener = unix::bind(&sock).unwrap();
        let broker = Broker::new(PinStore::in_memory(), Box::new(AlwaysYes));
        let server = Server::new(listener, broker);

        let client = async move {
            let mut conn = unix::connect(&sock_client).await.unwrap();
            let ca_b64 = b64(&chain.ca_der);
            let leaf_b64 = b64(&chain.kdc_leaf_der);
            conn.request_trust(
                "PQ.EXAMPLE.COM",
                "krbtgt/PQ.EXAMPLE.COM@PQ.EXAMPLE.COM",
                &leaf_b64,
                vec![ca_b64],
                true,
            )
            .await
            .unwrap()
            .unwrap();

            let store = conn.list_trusted_realms().await.unwrap().unwrap();
            let snippet = pkinit_trust_ctl::export(&store, &anchors_path).unwrap();

            let cert_path = anchors_path.join("PQ.EXAMPLE.COM.pem");
            assert!(snippet.contains(&format!("pkinit_anchors = FILE:{}", cert_path.display())));

            let pem = std::fs::read_to_string(&cert_path).unwrap();
            let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(body)
                .unwrap();
            assert_eq!(decoded, chain.ca_der);
        };

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
