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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemAlgorithm {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl KemAlgorithm {
    pub fn parameter_set_name(self) -> &'static str {
        match self {
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
        }
    }

    pub fn ciphertext_len(self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    pub fn encapsulation_key_len(self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }

    pub fn shared_secret_len(self) -> usize {
        32
    }

    pub fn oid(self) -> &'static [u32] {
        match self {
            Self::MlKem512 => ID_ML_KEM_512,
            Self::MlKem768 => ID_ML_KEM_768,
            Self::MlKem1024 => ID_ML_KEM_1024,
        }
    }

    pub fn from_oid(oid: &[u32]) -> Option<Self> {
        if oid == ID_ML_KEM_512 {
            Some(Self::MlKem512)
        } else if oid == ID_ML_KEM_768 {
            Some(Self::MlKem768)
        } else if oid == ID_ML_KEM_1024 {
            Some(Self::MlKem1024)
        } else {
            None
        }
    }
}

// Re-export PKINIT OIDs from synta-krb5 generated code
pub use synta_krb5::pkinit::{
    ID_PKINIT_AUTH_DATA, ID_PKINIT_DHKEY_DATA, ID_PKINIT_KDF_AH_SHA1, ID_PKINIT_KDF_AH_SHA256,
    ID_PKINIT_KDF_AH_SHA384, ID_PKINIT_KDF_AH_SHA512, ID_PKINIT_KPCLIENT_AUTH, ID_PKINIT_KPKDC,
    ID_PKINIT_RKEY_DATA, ID_PKINIT_SAN,
};

// ML-KEM OIDs (FIPS 203, RFC 9935)
pub use synta_certificate::oids::ML_KEM_512 as ID_ML_KEM_512;
pub use synta_certificate::oids::ML_KEM_768 as ID_ML_KEM_768;
pub use synta_certificate::oids::ML_KEM_1024 as ID_ML_KEM_1024;

// Composite ML-KEM OIDs (draft-ietf-lamps-pq-composite-kem)
pub const ID_MLKEM768_ECDH_P256: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 6, 59];
pub const ID_MLKEM768_X25519: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 6, 58];
pub const ID_MLKEM1024_ECDH_P384: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 6, 63];

// HKDF OID for KEM path KDF
pub use synta_certificate::hkdf_oid_2019_types::ID_ALG_HKDF_WITH_SHA512;

// CMS content type for KDCKEMInfo (id-pkinit arc, TBD by IANA)
pub const ID_PKINIT_KEM_KEY_DATA: &[u32] = &[1, 3, 6, 1, 5, 2, 3, 7];

// ML-DSA OIDs (FIPS 204, RFC 9935) — for downgrade prevention checks
pub use synta_certificate::oids::ML_DSA_44 as ID_ML_DSA_44;
pub use synta_certificate::oids::ML_DSA_65 as ID_ML_DSA_65;
pub use synta_certificate::oids::ML_DSA_87 as ID_ML_DSA_87;

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

    #[test]
    fn kem_algorithm_parameter_set_name() {
        assert_eq!(KemAlgorithm::MlKem512.parameter_set_name(), "ML-KEM-512");
        assert_eq!(KemAlgorithm::MlKem768.parameter_set_name(), "ML-KEM-768");
        assert_eq!(KemAlgorithm::MlKem1024.parameter_set_name(), "ML-KEM-1024");
    }

    #[test]
    fn kem_algorithm_sizes() {
        assert_eq!(KemAlgorithm::MlKem512.ciphertext_len(), 768);
        assert_eq!(KemAlgorithm::MlKem768.ciphertext_len(), 1088);
        assert_eq!(KemAlgorithm::MlKem1024.ciphertext_len(), 1568);

        assert_eq!(KemAlgorithm::MlKem512.encapsulation_key_len(), 800);
        assert_eq!(KemAlgorithm::MlKem768.encapsulation_key_len(), 1184);
        assert_eq!(KemAlgorithm::MlKem1024.encapsulation_key_len(), 1568);

        assert_eq!(KemAlgorithm::MlKem512.shared_secret_len(), 32);
        assert_eq!(KemAlgorithm::MlKem768.shared_secret_len(), 32);
        assert_eq!(KemAlgorithm::MlKem1024.shared_secret_len(), 32);
    }

    #[test]
    fn kem_algorithm_oid_roundtrip() {
        for alg in [
            KemAlgorithm::MlKem512,
            KemAlgorithm::MlKem768,
            KemAlgorithm::MlKem1024,
        ] {
            assert_eq!(KemAlgorithm::from_oid(alg.oid()), Some(alg));
        }
        assert_eq!(KemAlgorithm::from_oid(&[1, 2, 3]), None);
    }

    #[test]
    fn kem_oid_values() {
        assert_eq!(ID_ML_KEM_512, &[2, 16, 840, 1, 101, 3, 4, 4, 1]);
        assert_eq!(ID_ML_KEM_768, &[2, 16, 840, 1, 101, 3, 4, 4, 2]);
        assert_eq!(ID_ML_KEM_1024, &[2, 16, 840, 1, 101, 3, 4, 4, 3]);
    }

    #[test]
    fn composite_kem_oid_values() {
        assert_eq!(ID_MLKEM768_ECDH_P256, &[1, 3, 6, 1, 5, 5, 7, 6, 59]);
        assert_eq!(ID_MLKEM768_X25519, &[1, 3, 6, 1, 5, 5, 7, 6, 58]);
        assert_eq!(ID_MLKEM1024_ECDH_P384, &[1, 3, 6, 1, 5, 5, 7, 6, 63]);
    }
}
