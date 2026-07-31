use kurbu5_rs::Profile;
use pkinit_core::config::{PkinitClientConfig, PkinitKdcConfig};
use pkinit_core::constants::{DhGroup, KemAlgorithm};

pub fn read_client_config(profile: &Profile, realm: Option<&str>, config: &mut PkinitClientConfig) {
    if config.identity.is_none()
        && let Ok(v) = profile.get_string("libdefaults", "pkinit_identities", None, None)
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

    if let Some(realm) = realm {
        if config.identity.is_none()
            && let Ok(v) = profile.get_string("realms", realm, Some("pkinit_identities"), None)
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
