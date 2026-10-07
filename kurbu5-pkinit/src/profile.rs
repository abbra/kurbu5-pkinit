use kurbu5_rs::Profile;
use pkinit_core::config::{PkinitClientConfig, PkinitKdcConfig};
use pkinit_core::constants::{DhGroup, KemAlgorithm};

pub fn read_client_config(profile: &Profile, realm: Option<&str>, config: &mut PkinitClientConfig) {
    if config.identity.is_none()
        && let Ok(Some(v)) = profile.get_string_opt("libdefaults", "pkinit_identities", None)
    {
        config.identity = Some(v);
    }

    if config.anchors.is_empty()
        && let Ok(anchors) = profile.get_values(&["libdefaults", "pkinit_anchors"])
    {
        config.anchors = anchors;
    }
    if let Ok(pool) = profile.get_values(&["libdefaults", "pkinit_pool"]) {
        config.intermediates = pool;
    }
    if let Ok(revoke) = profile.get_values(&["libdefaults", "pkinit_revoke"]) {
        config.crls = revoke;
    }
    if let Ok(v) = profile.get_boolean("libdefaults", "pkinit_require_crl_checking", None, false) {
        config.require_crl_checking = v;
    }
    if let Ok(v) = profile.get_integer("libdefaults", "pkinit_dh_min_bits", None, 2048) {
        config.dh_min_bits = v as u32;
    }
    if let Ok(v) = profile.get_string("libdefaults", "pkinit_eku_checking", None, None) {
        apply_eku_checking(
            &v,
            &mut config.require_eku,
            &mut config.accept_secondary_eku,
        );
    }
    if let Ok(v) = profile.get_boolean("libdefaults", "pkinit_require_freshness_token", None, false)
    {
        config.require_freshness = v;
    }
    if let Ok(v) = profile.get_string("libdefaults", "pkinit_pqc_min_algorithm", None, None) {
        config.kem_algorithm = KemAlgorithm::from_name(&v);
    }
    if let Ok(v) = profile.get_boolean("libdefaults", "pkinit_kdc_trust_tofu", None, false) {
        config.kdc_trust_tofu = v;
    }
    if let Ok(v) = profile.get_string("libdefaults", "pkinit_kdc_trust_broker", None, None) {
        config.kdc_trust_broker = Some(v);
    }
    if let Ok(v) = profile.get_integer("libdefaults", "pkinit_kdc_trust_timeout", None, 30) {
        config.kdc_trust_timeout = v.clamp(0, i32::MAX) as u32;
    }

    if let Some(realm) = realm {
        if config.identity.is_none()
            && let Ok(Some(v)) = profile.get_string_opt("realms", realm, Some("pkinit_identities"))
        {
            config.identity = Some(v);
        }
        if config.anchors.is_empty()
            && let Ok(anchors) = profile.get_values(&["realms", realm, "pkinit_anchors"])
        {
            config.anchors = anchors;
        }
        if let Ok(pool) = profile.get_values(&["realms", realm, "pkinit_pool"]) {
            config.intermediates = pool;
        }
        if let Ok(revoke) = profile.get_values(&["realms", realm, "pkinit_revoke"]) {
            config.crls = revoke;
        }
        if let Ok(v) =
            profile.get_boolean("realms", realm, Some("pkinit_require_crl_checking"), false)
        {
            config.require_crl_checking = v;
        }
        if let Ok(v) = profile.get_integer("realms", realm, Some("pkinit_dh_min_bits"), 2048) {
            config.dh_min_bits = v as u32;
        }
        if let Ok(v) = profile.get_string("realms", realm, Some("pkinit_eku_checking"), None) {
            apply_eku_checking(
                &v,
                &mut config.require_eku,
                &mut config.accept_secondary_eku,
            );
        }
        if let Ok(v) = profile.get_string("realms", realm, Some("pkinit_pqc_min_algorithm"), None) {
            config.kem_algorithm = KemAlgorithm::from_name(&v);
        }
        if let Ok(v) = profile.get_boolean("realms", realm, Some("pkinit_kdc_trust_tofu"), false) {
            config.kdc_trust_tofu = v;
        }
        if let Ok(v) = profile.get_string("realms", realm, Some("pkinit_kdc_trust_broker"), None) {
            config.kdc_trust_broker = Some(v);
        }
        if let Ok(v) = profile.get_integer("realms", realm, Some("pkinit_kdc_trust_timeout"), 30) {
            config.kdc_trust_timeout = v.clamp(0, i32::MAX) as u32;
        }
    }

    config.dh_group = dh_group_from_min_bits(config.dh_min_bits);
}

pub fn read_kdc_config(profile: &Profile, realm: &str) -> PkinitKdcConfig {
    let mut config = PkinitKdcConfig::default();

    if let Ok(v) = profile.get_string("kdcdefaults", "pkinit_identity", None, None) {
        config.identity = Some(v);
    }
    if let Ok(anchors) = profile.get_values(&["kdcdefaults", "pkinit_anchors"]) {
        config.anchors = anchors;
    }
    if let Ok(pool) = profile.get_values(&["kdcdefaults", "pkinit_pool"]) {
        config.intermediates = pool;
    }
    if let Ok(revoke) = profile.get_values(&["kdcdefaults", "pkinit_revoke"]) {
        config.crls = revoke;
    }
    if let Ok(v) = profile.get_boolean("kdcdefaults", "pkinit_require_crl_checking", None, false) {
        config.require_crl_checking = v;
    }
    if let Ok(v) = profile.get_integer("kdcdefaults", "pkinit_dh_min_bits", None, 2048) {
        config.dh_min_bits = v as u32;
    }
    if let Ok(v) = profile.get_boolean("kdcdefaults", "pkinit_allow_upn", None, false) {
        config.allow_upn = v;
    }
    if let Ok(v) = profile.get_string("kdcdefaults", "pkinit_eku_checking", None, None) {
        apply_eku_checking(
            &v,
            &mut config.require_eku,
            &mut config.accept_secondary_eku,
        );
    }
    if let Ok(v) = profile.get_boolean("kdcdefaults", "pkinit_require_freshness_token", None, false)
    {
        config.require_freshness = v;
    }
    if let Ok(indicators) = profile.get_values(&["kdcdefaults", "pkinit_indicator"]) {
        config.auth_indicators = indicators;
    }
    if let Ok(v) = profile.get_string("kdcdefaults", "pkinit_pqc_min_algorithm", None, None)
        && let Some(alg) = KemAlgorithm::from_name(&v)
    {
        config.supported_kem_algorithms = alg.algorithms_at_or_above();
    }
    if let Ok(names) = profile.get_values(&["kdcdefaults", "pkinit_pqc_composite_algorithms"]) {
        config.supported_composite_kem_algorithms = names
            .iter()
            .filter_map(|n| KemAlgorithm::from_name(n))
            .collect();
    }

    if let Ok(v) = profile.get_string("realms", realm, Some("pkinit_identity"), None) {
        config.identity = Some(v);
    }
    if let Ok(anchors) = profile.get_values(&["realms", realm, "pkinit_anchors"]) {
        config.anchors = anchors;
    }
    if let Ok(pool) = profile.get_values(&["realms", realm, "pkinit_pool"]) {
        config.intermediates = pool;
    }
    if let Ok(revoke) = profile.get_values(&["realms", realm, "pkinit_revoke"]) {
        config.crls = revoke;
    }
    if let Ok(v) = profile.get_boolean("realms", realm, Some("pkinit_require_crl_checking"), false)
    {
        config.require_crl_checking = v;
    }
    if let Ok(v) = profile.get_integer("realms", realm, Some("pkinit_dh_min_bits"), 2048) {
        config.dh_min_bits = v as u32;
    }
    if let Ok(v) = profile.get_boolean("realms", realm, Some("pkinit_allow_upn"), false) {
        config.allow_upn = v;
    }
    if let Ok(v) = profile.get_string("realms", realm, Some("pkinit_eku_checking"), None) {
        apply_eku_checking(
            &v,
            &mut config.require_eku,
            &mut config.accept_secondary_eku,
        );
    }
    if let Ok(indicators) = profile.get_values(&["realms", realm, "pkinit_indicator"]) {
        config.auth_indicators = indicators;
    }
    if let Ok(v) = profile.get_string("realms", realm, Some("pkinit_pqc_min_algorithm"), None)
        && let Some(alg) = KemAlgorithm::from_name(&v)
    {
        config.supported_kem_algorithms = alg.algorithms_at_or_above();
    }
    if let Ok(names) = profile.get_values(&["realms", realm, "pkinit_pqc_composite_algorithms"]) {
        config.supported_composite_kem_algorithms = names
            .iter()
            .filter_map(|n| KemAlgorithm::from_name(n))
            .collect();
    }

    config
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
    use super::read_client_config;
    use kurbu5_rs::{Profile, sys};
    use pkinit_core::config::PkinitClientConfig;

    /// A `pkinit_identities` key placed only under `[realms]` must be read by
    /// `read_client_config`. Before the `Profile::get_string_opt` fix the
    /// libdefaults read used `get_string`, which returns `""` for an absent
    /// key and clobbered the `[realms]` value, leaving an empty identity
    /// (the token-E2E EINVAL). With `get_string_opt` the absent libdefaults
    /// key yields `None` and the `[realms]` value wins.
    ///
    /// This test sets the process-global `KRB5_CONFIG`; it is the only test
    /// in this crate that does so.
    #[test]
    fn client_identity_read_from_realms_not_clobbered_by_empty_libdefaults() {
        let dir =
            std::env::temp_dir().join(format!("kurbu5_pkinit_profile_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let conf = dir.join("krb5.conf");
        let conf_text = [
            "[libdefaults]",
            "    default_realm = PKINIT.TEST",
            "",
            "[realms]",
            "    PKINIT.TEST = {",
            "        kdc = 127.0.0.1:88",
            "        pkinit_identities = PKCS11:token=SmokeToken;object=mykey;type=private",
            "    }",
        ]
        .join("\n");
        std::fs::write(&conf, conf_text + "\n").expect("write temp config");
        // SAFETY: single-test crate; no other test mutates KRB5_CONFIG concurrently.
        unsafe { std::env::set_var("KRB5_CONFIG", &conf) };

        // SAFETY: standard krb5 init contract; ctx outlives the profile reads.
        let mut ctx: sys::krb5_context = std::ptr::null_mut();
        let code = unsafe { sys::krb5_init_context(&mut ctx) };
        assert_eq!(code, 0, "krb5_init_context failed");
        let profile = unsafe { Profile::from_raw_context(ctx) }.expect("profile");

        let mut cfg = PkinitClientConfig::default();
        read_client_config(&profile, Some("PKINIT.TEST"), &mut cfg);
        assert_eq!(
            cfg.identity.as_deref(),
            Some("PKCS11:token=SmokeToken;object=mykey;type=private")
        );

        // SAFETY: single-test crate; no other test mutates KRB5_CONFIG concurrently.
        unsafe { std::env::remove_var("KRB5_CONFIG") };
        // SAFETY: ctx is no longer needed.
        unsafe { sys::krb5_free_context(ctx) };
        let _ = std::fs::remove_dir_all(&dir);
    }
}
