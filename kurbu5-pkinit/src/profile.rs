use kurbu5_rs::Profile;
use pkinit_core::config::{PkinitClientConfig, PkinitKdcConfig};
use pkinit_core::constants::{DhGroup, KemAlgorithm};

/// A relation whose value cannot be used. Key-exchange settings are
/// security-relevant, so an unrecognized algorithm name is an error rather
/// than silently ignored: a typo would otherwise disable ML-KEM.
#[derive(Debug)]
pub struct ConfigError(String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

const KEM_NAMES: &str = "ML-KEM-512, ML-KEM-768, ML-KEM-1024, ML-KEM-768-X25519, \
                         ML-KEM-768-ECDH-P256, ML-KEM-1024-ECDH-P384";
const COMPOSITE_KEM_NAMES: &str = "ML-KEM-768-X25519, ML-KEM-768-ECDH-P256, ML-KEM-1024-ECDH-P384";

fn parse_kem_algorithm(key: &str, value: &str) -> Result<KemAlgorithm, ConfigError> {
    KemAlgorithm::from_name(value).ok_or_else(|| {
        ConfigError(format!(
            "{key}: unknown KEM algorithm {value:?} (expected one of {KEM_NAMES})"
        ))
    })
}

fn parse_composite_kem_algorithms(
    key: &str,
    values: &[String],
) -> Result<Vec<KemAlgorithm>, ConfigError> {
    values
        .iter()
        .map(|v| match KemAlgorithm::from_name(v) {
            Some(alg) if alg.is_composite() => Ok(alg),
            _ => Err(ConfigError(format!(
                "{key}: {v:?} is not a composite KEM algorithm \
                 (expected one of {COMPOSITE_KEM_NAMES})"
            ))),
        })
        .collect()
}

/// Reads PKINIT relations the way MIT krb5 does: a value under
/// `[realms] <realm>` takes precedence over the same relation in the defaults
/// section (`[libdefaults]` for the client, `[kdcdefaults]` for the KDC), and
/// a relation absent from both leaves the caller's current value untouched.
///
/// Every getter returns the merged value (or `None` when the relation is
/// absent everywhere), so an absent per-realm key can never override a
/// configured default -- which a plain `get_string`/`get_boolean` with a
/// hard-coded default does, since it cannot tell "absent" from "set".
struct Lookup<'a> {
    profile: &'a Profile,
    defaults: &'a str,
    realm: Option<&'a str>,
}

impl Lookup<'_> {
    fn string(&self, key: &str) -> Option<String> {
        if let Some(realm) = self.realm
            && let Ok(Some(v)) = self.profile.get_string_opt("realms", realm, Some(key))
        {
            return Some(v);
        }
        self.profile
            .get_string_opt(self.defaults, key, None)
            .ok()
            .flatten()
    }

    fn values(&self, key: &str) -> Option<Vec<String>> {
        if let Some(realm) = self.realm
            && let Ok(v) = self.profile.get_values(&["realms", realm, key])
            && !v.is_empty()
        {
            return Some(v);
        }
        self.profile
            .get_values(&[self.defaults, key])
            .ok()
            .filter(|v| !v.is_empty())
    }

    /// The default section's value falls through as the per-realm default,
    /// so the realm only wins when it actually sets the relation.
    fn boolean(&self, key: &str, current: bool) -> bool {
        let v = self
            .profile
            .get_boolean(self.defaults, key, None, current)
            .unwrap_or(current);
        match self.realm {
            Some(realm) => self
                .profile
                .get_boolean("realms", realm, Some(key), v)
                .unwrap_or(v),
            None => v,
        }
    }

    fn integer(&self, key: &str, current: i32) -> i32 {
        let v = self
            .profile
            .get_integer(self.defaults, key, None, current)
            .unwrap_or(current);
        match self.realm {
            Some(realm) => self
                .profile
                .get_integer("realms", realm, Some(key), v)
                .unwrap_or(v),
            None => v,
        }
    }
}

pub fn read_client_config(
    profile: &Profile,
    realm: Option<&str>,
    config: &mut PkinitClientConfig,
) -> Result<(), ConfigError> {
    let lookup = Lookup {
        profile,
        defaults: "libdefaults",
        realm,
    };

    // Identity and anchors may already be set by the caller (e.g. kinit -X
    // X509_user_identity / X509_anchors), which takes precedence.
    if config.identity.is_none() {
        config.identity = lookup.string("pkinit_identities");
    }
    if config.anchors.is_empty()
        && let Some(anchors) = lookup.values("pkinit_anchors")
    {
        config.anchors = anchors;
    }
    if let Some(pool) = lookup.values("pkinit_pool") {
        config.intermediates = pool;
    }
    if let Some(revoke) = lookup.values("pkinit_revoke") {
        config.crls = revoke;
    }
    config.require_crl_checking =
        lookup.boolean("pkinit_require_crl_checking", config.require_crl_checking);
    config.dh_min_bits = lookup.integer("pkinit_dh_min_bits", config.dh_min_bits as i32) as u32;
    if let Some(v) = lookup.string("pkinit_eku_checking") {
        apply_eku_checking(
            &v,
            &mut config.require_eku,
            &mut config.accept_secondary_eku,
        );
    }
    config.require_freshness =
        lookup.boolean("pkinit_require_freshness_token", config.require_freshness);
    if let Some(v) = lookup.string("pkinit_pqc_min_algorithm") {
        config.kem_algorithm = Some(parse_kem_algorithm("pkinit_pqc_min_algorithm", &v)?);
    }
    config.require_kem = lookup.boolean("pkinit_require_kem", config.require_kem);
    config.kdc_trust_tofu = lookup.boolean("pkinit_kdc_trust_tofu", config.kdc_trust_tofu);
    if let Some(v) = lookup.string("pkinit_kdc_trust_broker") {
        config.kdc_trust_broker = Some(v);
    }
    config.kdc_trust_timeout = lookup
        .integer("pkinit_kdc_trust_timeout", config.kdc_trust_timeout as i32)
        .clamp(0, i32::MAX) as u32;

    config.dh_group = dh_group_from_min_bits(config.dh_min_bits);
    Ok(())
}

pub fn read_kdc_config(profile: &Profile, realm: &str) -> Result<PkinitKdcConfig, ConfigError> {
    let mut config = PkinitKdcConfig::default();
    let lookup = Lookup {
        profile,
        defaults: "kdcdefaults",
        realm: Some(realm),
    };

    if let Some(v) = lookup.string("pkinit_identity") {
        config.identity = Some(v);
    }
    if let Some(anchors) = lookup.values("pkinit_anchors") {
        config.anchors = anchors;
    }
    if let Some(pool) = lookup.values("pkinit_pool") {
        config.intermediates = pool;
    }
    if let Some(revoke) = lookup.values("pkinit_revoke") {
        config.crls = revoke;
    }
    config.require_crl_checking =
        lookup.boolean("pkinit_require_crl_checking", config.require_crl_checking);
    config.dh_min_bits = lookup.integer("pkinit_dh_min_bits", config.dh_min_bits as i32) as u32;
    config.allow_upn = lookup.boolean("pkinit_allow_upn", config.allow_upn);
    if let Some(v) = lookup.string("pkinit_eku_checking") {
        apply_eku_checking(
            &v,
            &mut config.require_eku,
            &mut config.accept_secondary_eku,
        );
    }
    config.require_freshness =
        lookup.boolean("pkinit_require_freshness_token", config.require_freshness);
    if let Some(indicators) = lookup.values("pkinit_indicator") {
        config.auth_indicators = indicators;
    }
    if let Some(v) = lookup.string("pkinit_pqc_min_algorithm") {
        config.supported_kem_algorithms =
            parse_kem_algorithm("pkinit_pqc_min_algorithm", &v)?.algorithms_at_or_above();
    }
    if let Some(names) = lookup.values("pkinit_pqc_composite_algorithms") {
        config.supported_composite_kem_algorithms =
            parse_composite_kem_algorithms("pkinit_pqc_composite_algorithms", &names)?;
    }
    config.require_kem = lookup.boolean("pkinit_require_kem", config.require_kem);

    Ok(config)
}

fn apply_eku_checking(value: &str, require_eku: &mut bool, accept_secondary: &mut bool) {
    match value {
        "kpClientAuth" => {
            *require_eku = true;
            *accept_secondary = false;
        }
        "scLogin" => {
            *require_eku = true;
            *accept_secondary = true;
        }
        "none" => {
            *require_eku = false;
            *accept_secondary = false;
        }
        _ => {}
    }
}

fn dh_group_from_min_bits(min_bits: u32) -> DhGroup {
    if min_bits <= 256 {
        DhGroup::EcP256
    } else if min_bits <= 2048 {
        DhGroup::Oakley2048
    } else {
        DhGroup::Oakley4096
    }
}

#[cfg(test)]
mod tests {
    use super::{read_client_config, read_kdc_config};
    use kurbu5_rs::{Profile, sys};
    use pkinit_core::config::PkinitClientConfig;
    use pkinit_core::constants::KemAlgorithm;
    use std::sync::Mutex;

    /// `KRB5_CONFIG` is process-global; serialize every test that sets it.
    static KRB5_CONFIG_LOCK: Mutex<()> = Mutex::new(());

    /// Run `f` against a profile loaded from `lines` (a krb5.conf body).
    fn with_profile(lines: &[&str], f: impl FnOnce(&Profile)) {
        let _guard = KRB5_CONFIG_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile_dir();
        let conf = dir.join("krb5.conf");
        std::fs::write(&conf, lines.join("\n") + "\n").expect("write temp config");
        // SAFETY: KRB5_CONFIG_LOCK serializes every mutation of KRB5_CONFIG.
        unsafe { std::env::set_var("KRB5_CONFIG", &conf) };

        // SAFETY: standard krb5 init contract; ctx outlives the profile reads.
        let mut ctx: sys::krb5_context = std::ptr::null_mut();
        let code = unsafe { sys::krb5_init_context(&mut ctx) };
        assert_eq!(code, 0, "krb5_init_context failed");
        let profile = unsafe { Profile::from_raw_context(ctx) }.expect("profile");

        f(&profile);

        drop(profile);
        // SAFETY: KRB5_CONFIG_LOCK serializes every mutation of KRB5_CONFIG.
        unsafe { std::env::remove_var("KRB5_CONFIG") };
        // SAFETY: ctx is no longer needed.
        unsafe { sys::krb5_free_context(ctx) };
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tempfile_dir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "kurbu5_pkinit_profile_test_{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// A `pkinit_identities` key placed only under `[realms]` must be read by
    /// `read_client_config`: an absent `[libdefaults]` key must not leave an
    /// empty identity behind (the token-E2E EINVAL).
    #[test]
    fn client_identity_read_from_realms_not_clobbered_by_empty_libdefaults() {
        with_profile(
            &[
                "[libdefaults]",
                "    default_realm = PKINIT.TEST",
                "",
                "[realms]",
                "    PKINIT.TEST = {",
                "        kdc = 127.0.0.1:88",
                "        pkinit_identities = PKCS11:token=SmokeToken;object=mykey;type=private",
                "    }",
            ],
            |profile| {
                let mut cfg = PkinitClientConfig::default();
                read_client_config(profile, Some("PKINIT.TEST"), &mut cfg).unwrap();
                assert_eq!(
                    cfg.identity.as_deref(),
                    Some("PKCS11:token=SmokeToken;object=mykey;type=private")
                );
            },
        );
    }

    /// Relations set only in `[libdefaults]` must survive the per-realm pass
    /// when the realm stanza does not mention them -- strings, booleans,
    /// integers and lists alike.
    #[test]
    fn client_libdefaults_not_clobbered_by_absent_realm_keys() {
        with_profile(
            &[
                "[libdefaults]",
                "    default_realm = PKINIT.TEST",
                "    pkinit_pqc_min_algorithm = ML-KEM-1024",
                "    pkinit_require_kem = true",
                "    pkinit_kdc_trust_tofu = true",
                "    pkinit_kdc_trust_broker = /run/broker.sock",
                "    pkinit_kdc_trust_timeout = 90",
                "    pkinit_dh_min_bits = 4096",
                "    pkinit_pool = FILE:/etc/pki/pool.pem",
                "",
                "[realms]",
                "    PKINIT.TEST = {",
                "        kdc = 127.0.0.1:88",
                "    }",
            ],
            |profile| {
                let mut cfg = PkinitClientConfig::default();
                read_client_config(profile, Some("PKINIT.TEST"), &mut cfg).unwrap();
                assert_eq!(cfg.kem_algorithm, Some(KemAlgorithm::MlKem1024));
                assert!(cfg.require_kem);
                assert!(cfg.kdc_trust_tofu);
                assert_eq!(cfg.kdc_trust_broker.as_deref(), Some("/run/broker.sock"));
                assert_eq!(cfg.kdc_trust_timeout, 90);
                assert_eq!(cfg.dh_min_bits, 4096);
                assert_eq!(cfg.intermediates, vec!["FILE:/etc/pki/pool.pem"]);
                assert!(cfg.identity.is_none());
            },
        );
    }

    /// A per-realm value takes precedence over `[libdefaults]`, as in MIT
    /// krb5, and an identity preset by the caller (kinit -X) wins over both.
    #[test]
    fn client_realm_overrides_libdefaults() {
        let lines = [
            "[libdefaults]",
            "    default_realm = PKINIT.TEST",
            "    pkinit_identities = FILE:/default.pem,/default.key",
            "    pkinit_anchors = FILE:/default-ca.pem",
            "    pkinit_require_kem = true",
            "    pkinit_dh_min_bits = 4096",
            "",
            "[realms]",
            "    PKINIT.TEST = {",
            "        kdc = 127.0.0.1:88",
            "        pkinit_identities = FILE:/realm.pem,/realm.key",
            "        pkinit_anchors = FILE:/realm-ca.pem",
            "        pkinit_require_kem = false",
            "        pkinit_dh_min_bits = 2048",
            "    }",
        ];
        with_profile(&lines, |profile| {
            let mut cfg = PkinitClientConfig::default();
            read_client_config(profile, Some("PKINIT.TEST"), &mut cfg).unwrap();
            assert_eq!(cfg.identity.as_deref(), Some("FILE:/realm.pem,/realm.key"));
            assert_eq!(cfg.anchors, vec!["FILE:/realm-ca.pem"]);
            assert!(!cfg.require_kem);
            assert_eq!(cfg.dh_min_bits, 2048);

            let mut preset = PkinitClientConfig {
                identity: Some("FILE:/cli.pem,/cli.key".into()),
                ..Default::default()
            };
            read_client_config(profile, Some("PKINIT.TEST"), &mut preset).unwrap();
            assert_eq!(preset.identity.as_deref(), Some("FILE:/cli.pem,/cli.key"));
        });
    }

    /// The KDC side: `[kdcdefaults]` relations survive an absent per-realm
    /// key, and an identity configured nowhere stays `None` (not `""`).
    #[test]
    fn kdc_kdcdefaults_not_clobbered_by_absent_realm_keys() {
        with_profile(
            &[
                "[kdcdefaults]",
                "    pkinit_require_kem = true",
                "    pkinit_pqc_min_algorithm = ML-KEM-768",
                "    pkinit_allow_upn = true",
                "    pkinit_dh_min_bits = 4096",
                "    pkinit_anchors = FILE:/ca.pem",
                "    pkinit_pool = FILE:/pool.pem",
                "    pkinit_indicator = pkinit",
                "",
                "[realms]",
                "    PKINIT.TEST = {",
                "        database_module = db",
                "    }",
            ],
            |profile| {
                let cfg = read_kdc_config(profile, "PKINIT.TEST").unwrap();
                assert!(cfg.require_kem);
                assert_eq!(
                    cfg.supported_kem_algorithms,
                    vec![KemAlgorithm::MlKem768, KemAlgorithm::MlKem1024]
                );
                assert!(cfg.allow_upn);
                assert_eq!(cfg.dh_min_bits, 4096);
                assert_eq!(cfg.anchors, vec!["FILE:/ca.pem"]);
                assert_eq!(cfg.intermediates, vec!["FILE:/pool.pem"]);
                assert_eq!(cfg.auth_indicators, vec!["pkinit"]);
                assert!(cfg.identity.is_none());
            },
        );
    }

    #[test]
    fn kdc_realm_overrides_kdcdefaults() {
        with_profile(
            &[
                "[kdcdefaults]",
                "    pkinit_identity = FILE:/default.pem,/default.key",
                "    pkinit_require_kem = true",
                "",
                "[realms]",
                "    PKINIT.TEST = {",
                "        pkinit_identity = FILE:/realm.pem,/realm.key",
                "        pkinit_require_kem = false",
                "    }",
            ],
            |profile| {
                let cfg = read_kdc_config(profile, "PKINIT.TEST").unwrap();
                assert_eq!(cfg.identity.as_deref(), Some("FILE:/realm.pem,/realm.key"));
                assert!(!cfg.require_kem);
            },
        );
    }

    /// A misspelled algorithm must fail loudly: silently dropping it used to
    /// leave the client on classic DH/ECDH.
    #[test]
    fn client_unknown_pqc_algorithm_is_an_error() {
        with_profile(
            &[
                "[libdefaults]",
                "    default_realm = PKINIT.TEST",
                "    pkinit_pqc_min_algorithm = ML-KEM-786",
            ],
            |profile| {
                let mut cfg = PkinitClientConfig::default();
                let err = read_client_config(profile, Some("PKINIT.TEST"), &mut cfg).unwrap_err();
                assert!(err.to_string().contains("ML-KEM-786"), "{err}");
            },
        );
    }

    #[test]
    fn kdc_unknown_pqc_algorithm_is_an_error() {
        with_profile(
            &[
                "[realms]",
                "    PKINIT.TEST = {",
                "        pkinit_pqc_min_algorithm = mlkem",
                "    }",
            ],
            |profile| {
                let err = read_kdc_config(profile, "PKINIT.TEST").unwrap_err();
                assert!(
                    err.to_string().contains("pkinit_pqc_min_algorithm"),
                    "{err}"
                );
            },
        );
    }

    #[test]
    fn kdc_composite_algorithms_must_be_composite() {
        let base = ["[realms]", "    PKINIT.TEST = {"];
        with_profile(
            &[
                &base[..],
                &[
                    "        pkinit_pqc_composite_algorithms = ML-KEM-768-X25519",
                    "        pkinit_pqc_composite_algorithms = ML-KEM-1024-ECDH-P384",
                    "    }",
                ],
            ]
            .concat(),
            |profile| {
                let cfg = read_kdc_config(profile, "PKINIT.TEST").unwrap();
                assert_eq!(
                    cfg.supported_composite_kem_algorithms,
                    vec![
                        KemAlgorithm::MlKem768X25519,
                        KemAlgorithm::MlKem1024EcdhP384
                    ]
                );
            },
        );
        for bad in ["ML-KEM-768", "X25519"] {
            let line = format!("        pkinit_pqc_composite_algorithms = {bad}");
            with_profile(
                &[&base[..], &[line.as_str(), "    }"]].concat(),
                |profile| {
                    let err = read_kdc_config(profile, "PKINIT.TEST").unwrap_err();
                    assert!(err.to_string().contains(bad), "{err}");
                },
            );
        }
    }
}
