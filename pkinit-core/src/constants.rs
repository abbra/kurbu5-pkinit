#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhGroup {
    Oakley2048,
    Oakley4096,
    EcP256,
    EcP384,
    EcP521,
}

impl DhGroup {
    pub fn min_bits(self) -> u32 {
        match self {
            Self::Oakley2048 => 2048,
            Self::Oakley4096 => 4096,
            Self::EcP256 => 256,
            Self::EcP384 => 384,
            Self::EcP521 => 521,
        }
    }

    pub fn is_ec(self) -> bool {
        matches!(self, Self::EcP256 | Self::EcP384 | Self::EcP521)
    }
}

// Re-export PKINIT OIDs from synta-krb5 generated code
pub use synta_krb5::pkinit::{
    ID_PKINIT_AUTH_DATA, ID_PKINIT_DHKEY_DATA, ID_PKINIT_KDF_AH_SHA1,
    ID_PKINIT_KDF_AH_SHA256, ID_PKINIT_KDF_AH_SHA384, ID_PKINIT_KDF_AH_SHA512,
    ID_PKINIT_KPCLIENT_AUTH, ID_PKINIT_KPKDC, ID_PKINIT_RKEY_DATA, ID_PKINIT_SAN,
};

// Microsoft EKU/SAN OIDs — re-exported from synta-certificate (MicrosoftPKI.asn1)
pub use synta_certificate::oids::ID_MS_KP_SMARTCARD_LOGON;
pub use synta_certificate::oids::ID_MS_SAN_UPN;

// Common EKU OIDs — re-exported from synta-certificate
pub use synta_certificate::oids::KP_SERVER_AUTH as ID_KP_SERVER_AUTH;

// KDF preference order (server-side)
pub const KDF_PREFERENCE_ORDER: &[&[u32]] = &[
    ID_PKINIT_KDF_AH_SHA256,
    ID_PKINIT_KDF_AH_SHA1,
    ID_PKINIT_KDF_AH_SHA512,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dh_group_min_bits() {
        assert_eq!(DhGroup::Oakley2048.min_bits(), 2048);
        assert_eq!(DhGroup::Oakley4096.min_bits(), 4096);
        assert_eq!(DhGroup::EcP256.min_bits(), 256);
        assert_eq!(DhGroup::EcP384.min_bits(), 384);
        assert_eq!(DhGroup::EcP521.min_bits(), 521);
    }

    #[test]
    fn dh_group_is_ec() {
        assert!(!DhGroup::Oakley2048.is_ec());
        assert!(!DhGroup::Oakley4096.is_ec());
        assert!(DhGroup::EcP256.is_ec());
        assert!(DhGroup::EcP384.is_ec());
        assert!(DhGroup::EcP521.is_ec());
    }

    #[test]
    fn pkinit_oid_lengths() {
        assert_eq!(ID_PKINIT_AUTH_DATA.len(), 8);
        assert_eq!(ID_PKINIT_KPCLIENT_AUTH.len(), 8);
        assert_eq!(ID_PKINIT_KPKDC.len(), 8);
    }
}
