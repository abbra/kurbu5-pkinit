//! In-memory + on-disk pin store keyed by realm. Reference quality: a single
//! JSON file, one entry per realm, storing the pinned CA DER, its SHA-256,
//! and (for time-boxed grants) when the pin lapses.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use synta::Decoder;
use synta_certificate::DataHasher;
use synta_x509_verification::{
    ExtensionPolicy, OwnedStore, PolicyDefinition, ValidationProfile, VerificationCertificate,
};
use unicode_general_category::{GeneralCategory, get_general_category};

use pkinit_trust_proto::{Decision, TrustReply, TrustedRealm};

#[derive(Clone, Serialize, Deserialize)]
pub struct Pin {
    /// Base64 DER of the pinned CA certificate.
    pub ca_b64: String,
    /// Lowercase hex SHA-256 of the CA DER (for display).
    pub fingerprint: String,
    /// Unix time the grant lapses. `None` means the pin was granted
    /// "forever" and never expires on its own (only a changed CA revokes
    /// it). Absent in state files written before grants had a duration.
    #[serde(default)]
    pub expires_at: Option<u64>,
}

#[derive(Default, Serialize, Deserialize)]
pub struct PinStore {
    #[serde(skip)]
    path: Option<PathBuf>,
    pins: HashMap<String, Pin>,
}

/// How long an approved CA should be trusted before the broker forgets the
/// pin and asks again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantTtl {
    /// Trust indefinitely, until the realm presents a different CA.
    Forever,
    /// Trust for a bounded duration starting now.
    For(Duration),
}

impl GrantTtl {
    fn expires_at_epoch_secs(&self, now: u64) -> Option<u64> {
        match self {
            GrantTtl::Forever => None,
            GrantTtl::For(d) => Some(now.saturating_add(d.as_secs())),
        }
    }
}

/// Preset grant durations offered to the user, shortest first. Shared by
/// every interactive prompter so the choices stay consistent across UIs.
pub const GRANT_PRESETS: &[(&str, GrantTtl)] = &[
    ("15 minutes", GrantTtl::For(Duration::from_secs(15 * 60))),
    ("1 hour", GrantTtl::For(Duration::from_secs(60 * 60))),
    ("1 day", GrantTtl::For(Duration::from_secs(24 * 60 * 60))),
    (
        "1 week",
        GrantTtl::For(Duration::from_secs(7 * 24 * 60 * 60)),
    ),
    ("forever", GrantTtl::Forever),
];

/// How long an interactive prompt (tty or GUI notification) waits for a
/// response before failing closed. Shared so every prompter times out
/// consistently.
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(300);

/// Everything a prompter needs to show the user (or a log) what trust is
/// being requested.
pub struct TrustRequest<'a> {
    pub realm: &'a str,
    pub kdc_principal: &'a str,
    /// Subject DN of the CA the KDC presented.
    pub ca_subject: &'a str,
    /// Lowercase hex SHA-256 of the CA DER.
    pub fingerprint: &'a str,
    /// PID of the connecting client (the process that called the varlink
    /// method), from `SO_PEERCRED` on the socket. `None` if peer credentials
    /// couldn't be obtained (unsupported platform, or the lookup raced the
    /// peer exiting). Lets a prompter reach the client's own controlling
    /// terminal instead of (or in addition to) a desktop notification.
    pub client_pid: Option<i32>,
}

/// A prompter decides interactive (unknown-realm) requests. Returning
/// `Some(ttl)` approves and pins for that duration; `None` denies. `Send +
/// Sync` so the owning `Broker` can share it (via `Arc`) with the blocking
/// thread pool `decide()` runs on.
pub trait Prompter: Send + Sync {
    fn confirm(&self, req: &TrustRequest<'_>) -> Option<GrantTtl>;
}

/// A non-interactive prompter that always returns the same decision. Used in
/// CI and tests where no controlling terminal is available. An approval is
/// always granted "forever", matching pre-TTL automation semantics.
pub struct AutoPrompter {
    pub approve: bool,
}

impl Prompter for AutoPrompter {
    fn confirm(&self, _req: &TrustRequest<'_>) -> Option<GrantTtl> {
        self.approve.then_some(GrantTtl::Forever)
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// True for control characters (C0, DEL, C1) and any Unicode "Format" (`Cf`)
/// character — bidi overrides, zero-width/invisible joiners, deprecated
/// shaping controls, interlinear annotations, etc. — that can be used to
/// rewrite or hide displayed text without being a "control" character under
/// `char::is_control()`. Categorizing by `Cf` rather than hand-picking
/// ranges avoids missing individual format characters.
fn is_unsafe_for_display(c: char) -> bool {
    c.is_control() || get_general_category(c) == GeneralCategory::Format
}

/// Strips control and Unicode format characters from KDC-supplied text
/// before it reaches a trust prompt. `realm`, `kdc_principal`, and the CA
/// subject DN all originate from the unauthenticated side of a TOFU
/// exchange, so a malicious KDC could otherwise embed ANSI/OSC escape
/// sequences or bidi overrides to rewrite terminal output or hide the real
/// prompt from the user.
pub(crate) fn sanitize_for_display(s: &str) -> String {
    s.chars().filter(|c| !is_unsafe_for_display(*c)).collect()
}

/// Best-effort human-readable Subject DN of a DER certificate, for display in
/// trust prompts. `None` if the certificate can't be decoded — shouldn't
/// happen for `ca`, which has already validated as an anchor by this point.
fn subject_dn(der: &[u8]) -> Option<String> {
    let cert: synta_certificate::Certificate<'_> =
        Decoder::new(der, synta::Encoding::Der).decode().ok()?;
    Some(synta_certificate::format_dn(
        cert.tbs_certificate.subject.as_bytes(),
    ))
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
    /// A pin whose time-boxed grant has lapsed is forgotten and treated as an
    /// unknown realm (re-prompting rather than trusting or denying blindly).
    #[allow(clippy::too_many_arguments)]
    pub fn decide(
        &mut self,
        realm: &str,
        kdc_principal: &str,
        client_pid: Option<i32>,
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
        let now = now_secs();

        if let Some(existing) = self.pins.get(realm) {
            let expired = existing.expires_at.is_some_and(|exp| now >= exp);
            if !expired {
                return if existing.fingerprint == fp {
                    TrustReply {
                        decision: Decision::Trusted,
                        anchors: vec![existing.ca_b64.clone()],
                        reason: None,
                    }
                } else {
                    TrustReply {
                        decision: Decision::Denied,
                        anchors: vec![],
                        reason: Some("KDC CA changed for a known realm".into()),
                    }
                };
            }
        }
        // No live pin: either never seen, or a prior time-boxed grant lapsed.
        self.pins.remove(realm);

        if !interactive {
            return TrustReply {
                decision: Decision::Unknown,
                anchors: vec![],
                reason: None,
            };
        }

        let realm_display = sanitize_for_display(realm);
        let kdc_principal_display = sanitize_for_display(kdc_principal);
        let ca_subject = sanitize_for_display(
            &subject_dn(ca).unwrap_or_else(|| format!("(CA for {realm_display})")),
        );
        let req = TrustRequest {
            realm: &realm_display,
            kdc_principal: &kdc_principal_display,
            ca_subject: &ca_subject,
            fingerprint: &fp,
            client_pid,
        };
        match prompter.confirm(&req) {
            Some(ttl) => {
                self.pins.insert(
                    realm.to_string(),
                    Pin {
                        ca_b64: ca_b64.clone(),
                        fingerprint: fp,
                        expires_at: ttl.expires_at_epoch_secs(now),
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
            }
            None => TrustReply {
                decision: Decision::Denied,
                anchors: vec![],
                reason: Some("user declined".into()),
            },
        }
    }

    /// Every realm currently trusted (i.e. holding a live, unexpired pin),
    /// as the wire type a separate client uses to write permanent
    /// `pkinit_anchors` configuration. A lapsed grant is excluded, matching
    /// `decide`'s treatment of it as no longer trusted.
    pub fn trusted_realms(&self) -> Vec<TrustedRealm> {
        let now = now_secs();
        self.pins
            .iter()
            .filter(|(_, pin)| !pin.expires_at.is_some_and(|exp| now >= exp))
            .map(|(realm, pin)| TrustedRealm {
                realm: realm.clone(),
                ca_der: pin.ca_b64.clone(),
                fingerprint: pin.fingerprint.clone(),
                expires_at: pin.expires_at,
            })
            .collect()
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
    use pkinit_core::test_support::{build_kdc_chain, build_pq_kdc_chain};

    const KDC_PRINCIPAL: &str = "krbtgt/R@R";

    struct Yes;
    impl Prompter for Yes {
        fn confirm(&self, _req: &TrustRequest<'_>) -> Option<GrantTtl> {
            Some(GrantTtl::Forever)
        }
    }

    struct No;
    impl Prompter for No {
        fn confirm(&self, _req: &TrustRequest<'_>) -> Option<GrantTtl> {
            None
        }
    }

    /// Grants approval that lapses the instant it's issued (TTL of 0
    /// seconds), so the very next `decide()` call sees it as expired.
    struct ExpiredOnArrival;
    impl Prompter for ExpiredOnArrival {
        fn confirm(&self, _req: &TrustRequest<'_>) -> Option<GrantTtl> {
            Some(GrantTtl::For(Duration::from_secs(0)))
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

    /// Same shape as `alice()`, but the CA is ML-DSA-65 (post-quantum)
    /// rather than ECDSA — chain validation must not assume the anchor's
    /// signature algorithm.
    fn carol_pq() -> (Vec<u8>, Vec<Vec<u8>>) {
        let chain = build_pq_kdc_chain("CAROL.PQ");
        (chain.kdc_leaf_der, vec![chain.ca_der])
    }

    #[test]
    fn unknown_non_interactive_is_unknown() {
        let mut store = PinStore::in_memory();
        let (signer, certs) = alice();
        let r = store.decide("R", KDC_PRINCIPAL, None, &signer, &certs, false, &No);
        assert_eq!(r.decision, Decision::Unknown);
    }

    #[test]
    fn unknown_interactive_yes_pins_then_trusts_again() {
        let mut store = PinStore::in_memory();
        let (signer, certs) = alice();
        let first = store.decide("R", KDC_PRINCIPAL, None, &signer, &certs, true, &Yes);
        assert_eq!(first.decision, Decision::Trusted);
        let second = store.decide("R", KDC_PRINCIPAL, None, &signer, &certs, false, &No);
        assert_eq!(second.decision, Decision::Trusted);
    }

    #[test]
    fn changed_ca_is_denied() {
        let mut store = PinStore::in_memory();
        let (signer_a, certs_a) = alice();
        let _ = store.decide("R", KDC_PRINCIPAL, None, &signer_a, &certs_a, true, &Yes);
        let (signer_b, certs_b) = bob();
        let changed = store.decide("R", KDC_PRINCIPAL, None, &signer_b, &certs_b, true, &Yes);
        assert_eq!(changed.decision, Decision::Denied);
    }

    #[test]
    fn unknown_interactive_no_is_denied() {
        let mut store = PinStore::in_memory();
        let (signer, certs) = alice();
        let r = store.decide("R", KDC_PRINCIPAL, None, &signer, &certs, true, &No);
        assert_eq!(r.decision, Decision::Denied);
    }

    #[test]
    fn empty_chain_is_denied() {
        let mut store = PinStore::in_memory();
        let r = store.decide("R", KDC_PRINCIPAL, None, b"leaf", &[], true, &Yes);
        assert_eq!(r.decision, Decision::Denied);
    }

    #[test]
    fn leaf_only_chain_is_denied() {
        let mut store = PinStore::in_memory();
        let (signer, _) = alice();
        let certs = vec![signer.clone()];
        let r = store.decide("R", KDC_PRINCIPAL, None, &signer, &certs, true, &Yes);
        assert_eq!(r.decision, Decision::Denied);
    }

    #[test]
    fn auto_prompter_returns_its_decision() {
        let req = TrustRequest {
            realm: "R",
            kdc_principal: KDC_PRINCIPAL,
            ca_subject: "CN=CA",
            fingerprint: "fp",
            client_pid: None,
        };
        assert_eq!(
            AutoPrompter { approve: true }.confirm(&req),
            Some(GrantTtl::Forever)
        );
        assert_eq!(AutoPrompter { approve: false }.confirm(&req), None);
    }

    #[test]
    fn empty_chain_on_known_realm_denies() {
        let mut store = PinStore::in_memory();
        let (signer, certs) = alice();
        let _ = store.decide("R", KDC_PRINCIPAL, None, &signer, &certs, true, &Yes);
        let empty = store.decide("R", KDC_PRINCIPAL, None, &signer, &[], true, &Yes);
        assert_eq!(empty.decision, Decision::Denied);
    }

    #[test]
    fn open_persists_and_reloads_pins() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.json");
        let (signer, certs) = alice();
        let mut store = PinStore::open(path.clone()).unwrap();
        let first = store.decide("R", KDC_PRINCIPAL, None, &signer, &certs, true, &Yes);
        assert_eq!(first.decision, Decision::Trusted);
        assert!(path.exists());
        let mut reloaded = PinStore::open(path).unwrap();
        let again = reloaded.decide("R", KDC_PRINCIPAL, None, &signer, &certs, false, &No);
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
        let r = store.decide("R", KDC_PRINCIPAL, None, &signer, &certs, true, &Yes);
        assert_eq!(r.decision, Decision::Denied);
    }

    #[test]
    fn expired_grant_is_forgotten_not_denied() {
        // A pin whose TTL has already lapsed must be treated as if the
        // realm were unknown (re-prompt / Unknown), not as a live pin (which
        // would either wrongly Trust or wrongly Deny-as-"CA changed").
        let mut store = PinStore::in_memory();
        let (signer, certs) = alice();
        let first = store.decide(
            "R",
            KDC_PRINCIPAL,
            None,
            &signer,
            &certs,
            true,
            &ExpiredOnArrival,
        );
        assert_eq!(first.decision, Decision::Trusted);

        let noninteractive = store.decide("R", KDC_PRINCIPAL, None, &signer, &certs, false, &No);
        assert_eq!(noninteractive.decision, Decision::Unknown);
    }

    #[test]
    fn expired_grant_reprompts_and_can_be_retrusted() {
        let mut store = PinStore::in_memory();
        let (signer, certs) = alice();
        let _ = store.decide(
            "R",
            KDC_PRINCIPAL,
            None,
            &signer,
            &certs,
            true,
            &ExpiredOnArrival,
        );
        let again = store.decide("R", KDC_PRINCIPAL, None, &signer, &certs, true, &Yes);
        assert_eq!(again.decision, Decision::Trusted);
    }

    #[test]
    fn finite_grant_persists_expiry_and_survives_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.json");
        let (signer, certs) = alice();

        struct OneHour;
        impl Prompter for OneHour {
            fn confirm(&self, _req: &TrustRequest<'_>) -> Option<GrantTtl> {
                Some(GrantTtl::For(Duration::from_secs(3600)))
            }
        }

        let mut store = PinStore::open(path.clone()).unwrap();
        let first = store.decide("R", KDC_PRINCIPAL, None, &signer, &certs, true, &OneHour);
        assert_eq!(first.decision, Decision::Trusted);

        // Not yet expired: a fresh store loaded from disk must still trust
        // it non-interactively.
        let mut reloaded = PinStore::open(path).unwrap();
        let again = reloaded.decide("R", KDC_PRINCIPAL, None, &signer, &certs, false, &No);
        assert_eq!(again.decision, Decision::Trusted);
    }

    #[test]
    fn trusted_realms_lists_live_pins_with_wire_fields() {
        let mut store = PinStore::in_memory();
        let (signer, certs) = alice();
        let ca_b64 = base64::engine::general_purpose::STANDARD.encode(&certs[0]);
        let fp = PinStore::sha256_hex(&certs[0]);

        let _ = store.decide("R", KDC_PRINCIPAL, None, &signer, &certs, true, &Yes);

        let realms = store.trusted_realms();
        assert_eq!(realms.len(), 1);
        assert_eq!(realms[0].realm, "R");
        assert_eq!(realms[0].ca_der, ca_b64);
        assert_eq!(realms[0].fingerprint, fp);
        assert_eq!(realms[0].expires_at, None);
    }

    #[test]
    fn trusted_realms_excludes_expired_pins() {
        let mut store = PinStore::in_memory();
        let (signer, certs) = alice();
        let _ = store.decide(
            "R",
            KDC_PRINCIPAL,
            None,
            &signer,
            &certs,
            true,
            &ExpiredOnArrival,
        );
        assert_eq!(store.trusted_realms(), vec![]);
    }

    #[test]
    fn trusted_realms_reports_finite_expiry() {
        let mut store = PinStore::in_memory();
        let (signer, certs) = alice();

        struct OneHour;
        impl Prompter for OneHour {
            fn confirm(&self, _req: &TrustRequest<'_>) -> Option<GrantTtl> {
                Some(GrantTtl::For(Duration::from_secs(3600)))
            }
        }

        let before = now_secs();
        let _ = store.decide("R", KDC_PRINCIPAL, None, &signer, &certs, true, &OneHour);
        let after = now_secs();

        let realms = store.trusted_realms();
        assert_eq!(realms.len(), 1);
        let expires_at = realms[0].expires_at.expect("finite grant has an expiry");
        assert!(expires_at >= before + 3600 && expires_at <= after + 3600);
    }

    #[test]
    fn post_quantum_ca_is_pinned_then_trusted_again() {
        // Chain validation (select_ca / validates_as_anchor) must accept an
        // ML-DSA-signed anchor exactly like an ECDSA one — nothing in the
        // decision path may assume a particular signature algorithm.
        let mut store = PinStore::in_memory();
        let (signer, certs) = carol_pq();
        let first = store.decide("R", KDC_PRINCIPAL, None, &signer, &certs, true, &Yes);
        assert_eq!(first.decision, Decision::Trusted);

        let second = store.decide("R", KDC_PRINCIPAL, None, &signer, &certs, false, &No);
        assert_eq!(second.decision, Decision::Trusted);
    }

    #[test]
    fn sanitize_for_display_strips_control_characters() {
        // ESC (ANSI/OSC sequences), C1 controls, and DEL must all be
        // dropped, neutralizing escape sequences by removing the
        // introducer byte; ordinary printable text (including non-ASCII)
        // survives untouched.
        assert_eq!(
            sanitize_for_display("R\x1bealm\u{9b}\u{7f} \u{e9}cole"),
            "Realm école"
        );
    }

    #[test]
    fn sanitize_for_display_strips_unicode_format_characters() {
        // Bidi overrides and zero-width characters aren't "control"
        // characters under Unicode, but can still be used to visually
        // reorder or hide text in a terminal or GUI trust prompt.
        assert_eq!(
            sanitize_for_display("R\u{202E}ealm\u{200B}\u{FEFF}"),
            "Realm"
        );
    }

    #[test]
    fn sanitize_for_display_strips_less_common_format_characters() {
        // U+061C, U+180E, U+206A-U+206F, and U+FFF9-U+FFFB are all Unicode
        // category Cf, but sit outside the ranges a hand-picked list would
        // typically include; categorizing by Cf catches them regardless.
        assert_eq!(
            sanitize_for_display("R\u{061C}e\u{180E}a\u{206A}l\u{FFF9}m\u{FFFB}"),
            "Realm"
        );
    }

    #[test]
    fn trusted_realms_reports_post_quantum_ca() {
        let mut store = PinStore::in_memory();
        let (signer, certs) = carol_pq();
        let ca_b64 = base64::engine::general_purpose::STANDARD.encode(&certs[0]);
        let fp = PinStore::sha256_hex(&certs[0]);

        let _ = store.decide("R", KDC_PRINCIPAL, None, &signer, &certs, true, &Yes);

        let realms = store.trusted_realms();
        assert_eq!(realms.len(), 1);
        assert_eq!(realms[0].ca_der, ca_b64);
        assert_eq!(realms[0].fingerprint, fp);
    }
}
