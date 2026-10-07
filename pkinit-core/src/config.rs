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
    /// Refuse classic DH/ECDH: always use a KEM (ML-KEM-768 unless
    /// `kem_algorithm` names another) and never fall back to DH/ECDH when the
    /// KDC offers it, whatever algorithm the client certificate uses.
    pub require_kem: bool,
    pub identity: Option<String>,
    pub anchors: Vec<String>,
    pub intermediates: Vec<String>,
    pub crls: Vec<String>,
    pub kdc_trust_tofu: bool,
    pub kdc_trust_broker: Option<String>,
    pub kdc_trust_timeout: u32,
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
            require_kem: false,
            identity: None,
            anchors: Vec::new(),
            intermediates: Vec::new(),
            crls: Vec::new(),
            kdc_trust_tofu: false,
            kdc_trust_broker: None,
            kdc_trust_timeout: 30,
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
    /// Composite ML-KEM algorithms the KDC accepts, in addition to
    /// `supported_kem_algorithms`. Explicit opt-in list (not a category
    /// floor like `supported_kem_algorithms`): each composite variant pairs
    /// a specific traditional algorithm, so "at or above" doesn't apply.
    pub supported_composite_kem_algorithms: Vec<KemAlgorithm>,
    /// Reject classic DH/ECDH requests with
    /// `KDC_ERR_EPHEMERAL_KEY_PARAMS_NOT_ACCEPTED`, listing only KEM
    /// algorithms in the typed data, so only a post-quantum key exchange
    /// succeeds. With no KEM floor configured, every ML-KEM parameter set
    /// is accepted and advertised.
    pub require_kem: bool,
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
            supported_composite_kem_algorithms: Vec::new(),
            require_kem: false,
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
    fn client_config_tofu_defaults() {
        let c = PkinitClientConfig::default();
        assert!(!c.kdc_trust_tofu);
        assert!(c.kdc_trust_broker.is_none());
        assert_eq!(c.kdc_trust_timeout, 30);
    }

    #[test]
    fn kdc_config_defaults() {
        let c = PkinitKdcConfig::default();
        assert!(c.require_eku);
        assert_eq!(c.dh_min_bits, 2048);
        assert!(c.auth_indicators.is_empty());
    }
}
