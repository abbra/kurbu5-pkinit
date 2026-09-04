//! In-memory + on-disk pin store keyed by realm. Reference quality: a single
//! JSON file, one entry per realm, storing the pinned CA DER and its SHA-256.

use std::collections::HashMap;
use std::path::PathBuf;

use base64::Engine;
use serde::{Deserialize, Serialize};
use synta::Decoder;
use synta_certificate::DataHasher;
use synta_x509_verification::{
    ExtensionPolicy, OwnedStore, PolicyDefinition, ValidationProfile, VerificationCertificate,
};

use pkinit_trust_proto::{Decision, TrustReply};

#[derive(Clone, Serialize, Deserialize)]
pub struct Pin {
    /// Base64 DER of the pinned CA certificate.
    pub ca_b64: String,
    /// Lowercase hex SHA-256 of the CA DER (for display).
    pub fingerprint: String,
}

#[derive(Default, Serialize, Deserialize)]
pub struct PinStore {
    #[serde(skip)]
    path: Option<PathBuf>,
    pins: HashMap<String, Pin>,
}

/// A prompter decides interactive (unknown-realm) requests. Returning `true`
/// approves and pins; `false` denies. `Send` so the owning `Broker` service
/// stays `Send` for the zlink server.
pub trait Prompter: Send {
    fn confirm(&self, realm: &str, subject: &str, fingerprint: &str) -> bool;
}

/// A non-interactive prompter that always returns the same decision. Used in
/// CI and tests where no controlling terminal is available.
pub struct AutoPrompter {
    pub approve: bool,
}

impl Prompter for AutoPrompter {
    fn confirm(&self, _realm: &str, _subject: &str, _fingerprint: &str) -> bool {
        self.approve
    }
}

/// Validate that `anchor_der` is a CA that terminates the presented signer
/// chain. `synta-x509-verification` enforces BasicConstraints, keyCertSign,
/// certificate validity, signatures, and path construction; the broker does
/// not duplicate those checks by inspecting extensions manually.
fn validates_as_anchor(anchor_der: &[u8], signer_der: &[u8], presented_der: &[Vec<u8>]) -> bool {
    let store = match OwnedStore::try_new(std::iter::once(anchor_der)) {
        Ok(store) => store,
        Err(_) => return false,
    };
    let leaf_cert = match Decoder::new(signer_der, synta::Encoding::Der).decode() {
        Ok(cert) => cert,
        Err(_) => return false,
    };
    let leaf = VerificationCertificate::new(leaf_cert, signer_der);
    let mut intermediates = Vec::with_capacity(presented_der.len());
    for der in presented_der {
        if der.as_slice() == signer_der || der.as_slice() == anchor_der {
            continue;
        }
        let Ok(cert) = Decoder::new(der, synta::Encoding::Der).decode() else {
            return false;
        };
        intermediates.push(VerificationCertificate::new(cert, der));
    }

    let verifier = synta_certificate::default_signature_verifier();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let mut policy = PolicyDefinition::new_client(verifier, now);
    policy.profile = ValidationProfile::Rfc5280;
    policy.extended_key_usage = None;
    policy.permitted_spki_algorithms =
        synta_x509_verification::WEBPKI_PERMITTED_SPKI_ALGORITHMS_WITH_PQ;
    policy.permitted_signature_algorithms =
        synta_x509_verification::WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS_WITH_PQ;
    policy.ca_extension_policy = ExtensionPolicy::new_default_webpki_ca();
    policy.ee_extension_policy = ExtensionPolicy::new_permit_all();

    synta_x509_verification::verify(
        &leaf,
        &intermediates,
        &policy,
        store.as_store(),
        Default::default(),
    )
    .is_ok()
}
impl PinStore {
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Open a persistent store backed by `path`. Existing pins are loaded if the
    /// file exists; a state file that fails to parse is reported and treated as
    /// empty (re-prompting unknown realms rather than trusting blindly). Later
    /// approvals are written back to `path`.
    pub fn open(path: PathBuf) -> std::io::Result<Self> {
        let pins = if path.exists() {
            let data = std::fs::read(&path)?;
            match serde_json::from_slice(&data) {
                Ok(pins) => pins,
                Err(e) => {
                    eprintln!(
                        "[broker] warning: state file {} unreadable ({}); starting empty",
                        path.display(),
                        e
                    );
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };
        Ok(Self {
            path: Some(path),
            pins,
        })
    }

    /// Choose a CA to pin from the presented chain. The signer certificate is
    /// never eligible, and no fallback anchor exists when no presented CA
    /// validates the signer chain.
    fn select_ca<'a>(signer_der: &[u8], presented_der: &'a [Vec<u8>]) -> Option<&'a Vec<u8>> {
        presented_der.iter().rev().find(|der| {
            der.as_slice() != signer_der && validates_as_anchor(der, signer_der, presented_der)
        })
    }

    fn sha256_hex(der: &[u8]) -> String {
        let hasher = synta_certificate::default_data_hasher();
        let digest = hasher.hash_data("sha256", der).expect("sha256 digest");
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Apply the decision table. Fail closed when the presented CMS chain has
    /// no valid CA certificate; the KDC signer is never used as a fallback.
    pub fn decide(
        &mut self,
        realm: &str,
        subject: &str,
        signer_der: &[u8],
        presented_der: &[Vec<u8>],
        interactive: bool,
        prompter: &dyn Prompter,
    ) -> TrustReply {
        let Some(ca) = Self::select_ca(signer_der, presented_der) else {
            return TrustReply {
                decision: Decision::Denied,
                anchors: vec![],
                reason: Some("presented chain contains no valid CA certificate".into()),
            };
        };
        let fp = Self::sha256_hex(ca);
        let ca_b64 = base64::engine::general_purpose::STANDARD.encode(ca);

        match self.pins.get(realm) {
            Some(existing) if existing.fingerprint == fp => TrustReply {
                decision: Decision::Trusted,
                anchors: vec![existing.ca_b64.clone()],
                reason: None,
            },
            Some(_) => TrustReply {
                decision: Decision::Denied,
                anchors: vec![],
                reason: Some("KDC CA changed for a known realm".into()),
            },
            None => {
                if !interactive {
                    return TrustReply {
                        decision: Decision::Unknown,
                        anchors: vec![],
                        reason: None,
                    };
                }
                if prompter.confirm(realm, subject, &fp) {
                    self.pins.insert(
                        realm.to_string(),
                        Pin {
                            ca_b64: ca_b64.clone(),
                            fingerprint: fp,
                        },
                    );
                    if let Err(e) = self.persist() {
                        eprintln!("[broker] warning: failed to persist pins: {e}");
                    }
                    TrustReply {
                        decision: Decision::Trusted,
                        anchors: vec![ca_b64],
                        reason: None,
                    }
                } else {
                    TrustReply {
                        decision: Decision::Denied,
                        anchors: vec![],
                        reason: Some("user declined".into()),
                    }
                }
            }
        }
    }

    fn persist(&self) -> std::io::Result<()> {
        if let Some(path) = &self.path {
            let json = serde_json::to_vec_pretty(&self.pins).unwrap_or_default();
            std::fs::write(path, json)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkinit_core::test_support::build_kdc_chain;

    struct Yes;
    impl Prompter for Yes {
        fn confirm(&self, _: &str, _: &str, _: &str) -> bool {
            true
        }
    }

    struct No;
    impl Prompter for No {
        fn confirm(&self, _: &str, _: &str, _: &str) -> bool {
            false
        }
    }

    fn alice() -> (Vec<u8>, Vec<Vec<u8>>) {
        let chain = build_kdc_chain("A.LICE");
        (chain.kdc_leaf_der, vec![chain.ca_der])
    }

    fn bob() -> (Vec<u8>, Vec<Vec<u8>>) {
        let chain = build_kdc_chain("B.OB");
        (chain.kdc_leaf_der, vec![chain.ca_der])
    }

    #[test]
    fn unknown_non_interactive_is_unknown() {
        let mut store = PinStore::in_memory();
        let (signer, certs) = alice();
        let r = store.decide("R", "CN=CA", &signer, &certs, false, &No);
        assert_eq!(r.decision, Decision::Unknown);
    }

    #[test]
    fn unknown_interactive_yes_pins_then_trusts_again() {
        let mut store = PinStore::in_memory();
        let (signer, certs) = alice();
        let first = store.decide("R", "CN=CA", &signer, &certs, true, &Yes);
        assert_eq!(first.decision, Decision::Trusted);
        let second = store.decide("R", "CN=CA", &signer, &certs, false, &No);
        assert_eq!(second.decision, Decision::Trusted);
    }

    #[test]
    fn changed_ca_is_denied() {
        let mut store = PinStore::in_memory();
        let (signer_a, certs_a) = alice();
        let _ = store.decide("R", "CN=CA", &signer_a, &certs_a, true, &Yes);
        let (signer_b, certs_b) = bob();
        let changed = store.decide("R", "CN=CA", &signer_b, &certs_b, true, &Yes);
        assert_eq!(changed.decision, Decision::Denied);
    }

    #[test]
    fn unknown_interactive_no_is_denied() {
        let mut store = PinStore::in_memory();
        let (signer, certs) = alice();
        let r = store.decide("R", "CN=CA", &signer, &certs, true, &No);
        assert_eq!(r.decision, Decision::Denied);
    }

    #[test]
    fn empty_chain_is_denied() {
        let mut store = PinStore::in_memory();
        let r = store.decide("R", "CN=CA", b"leaf", &[], true, &Yes);
        assert_eq!(r.decision, Decision::Denied);
    }

    #[test]
    fn leaf_only_chain_is_denied() {
        let mut store = PinStore::in_memory();
        let (signer, _) = alice();
        let certs = vec![signer.clone()];
        let r = store.decide("R", "CN=KDC", &signer, &certs, true, &Yes);
        assert_eq!(r.decision, Decision::Denied);
    }

    #[test]
    fn auto_prompter_returns_its_decision() {
        assert!(AutoPrompter { approve: true }.confirm("R", "s", "fp"));
        assert!(!AutoPrompter { approve: false }.confirm("R", "s", "fp"));
    }

    #[test]
    fn empty_chain_on_known_realm_denies() {
        let mut store = PinStore::in_memory();
        let (signer, certs) = alice();
        let _ = store.decide("R", "CN=CA", &signer, &certs, true, &Yes);
        let empty = store.decide("R", "CN=CA", &signer, &[], true, &Yes);
        assert_eq!(empty.decision, Decision::Denied);
    }

    #[test]
    fn open_persists_and_reloads_pins() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.json");
        let (signer, certs) = alice();
        let mut store = PinStore::open(path.clone()).unwrap();
        let first = store.decide("R", "CN=CA", &signer, &certs, true, &Yes);
        assert_eq!(first.decision, Decision::Trusted);
        assert!(path.exists());
        let mut reloaded = PinStore::open(path).unwrap();
        let again = reloaded.decide("R", "CN=CA", &signer, &certs, false, &No);
        assert_eq!(again.decision, Decision::Trusted);
    }

    #[test]
    fn seeded_mismatch_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.json");
        let seed = r#"{"R":{"ca_b64":"Ym9ndXM=","fingerprint":"0000000000000000000000000000000000000000000000000000000000000000"}}"#;
        std::fs::write(&path, seed).unwrap();
        let mut store = PinStore::open(path).unwrap();
        let (signer, certs) = alice();
        let r = store.decide("R", "CN=CA", &signer, &certs, true, &Yes);
        assert_eq!(r.decision, Decision::Denied);
    }
}
