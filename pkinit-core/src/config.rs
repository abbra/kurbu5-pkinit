use crate::constants::{DhGroup, KemAlgorithm};

#[derive(Debug, Clone)]
pub struct PkinitClientConfig {
    pub require_eku: bool,
    pub accept_secondary_eku: bool,
    pub allow_upn: bool,
    pub require_crl_checking: bool,
    pub require_freshness: bool,
    pub disable_freshness: bool,
    pub dh_min_bits: u32,
    pub dh_group: DhGroup,
    pub kem_algorithm: Option<KemAlgorithm>,
    pub identity: Option<String>,
    pub anchors: Vec<String>,
    pub intermediates: Vec<String>,
    pub crls: Vec<String>,
}

impl Default for PkinitClientConfig {
    fn default() -> Self {
        Self {
            require_eku: true,
            accept_secondary_eku: false,
            allow_upn: false,
            require_crl_checking: false,
            require_freshness: false,
            disable_freshness: false,
            dh_min_bits: 2048,
            dh_group: DhGroup::Oakley2048,
            kem_algorithm: None,
            identity: None,
            anchors: Vec::new(),
            intermediates: Vec::new(),
            crls: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PkinitKdcConfig {
    pub require_eku: bool,
    pub accept_secondary_eku: bool,
    pub allow_upn: bool,
    pub require_crl_checking: bool,
    pub require_freshness: bool,
    pub dh_min_bits: u32,
    pub identity: Option<String>,
    pub anchors: Vec<String>,
    pub intermediates: Vec<String>,
    pub crls: Vec<String>,
    pub auth_indicators: Vec<String>,
    pub supported_kem_algorithms: Vec<KemAlgorithm>,
}

impl Default for PkinitKdcConfig {
    fn default() -> Self {
        Self {
            require_eku: true,
            accept_secondary_eku: false,
            allow_upn: false,
            require_crl_checking: false,
            require_freshness: false,
            dh_min_bits: 2048,
            identity: None,
            anchors: Vec::new(),
            intermediates: Vec::new(),
            crls: Vec::new(),
            auth_indicators: Vec::new(),
            supported_kem_algorithms: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_config_defaults() {
        let c = PkinitClientConfig::default();
        assert!(c.require_eku);
        assert!(!c.accept_secondary_eku);
        assert!(!c.allow_upn);
        assert_eq!(c.dh_min_bits, 2048);
        assert_eq!(c.dh_group, DhGroup::Oakley2048);
        assert!(c.identity.is_none());
    }

    #[test]
    fn kdc_config_defaults() {
        let c = PkinitKdcConfig::default();
        assert!(c.require_eku);
        assert_eq!(c.dh_min_bits, 2048);
        assert!(c.auth_indicators.is_empty());
    }
}
