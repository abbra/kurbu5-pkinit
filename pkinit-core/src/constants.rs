#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KemAlgorithm {
    MlKem512,
    MlKem768,
    MlKem1024,
    /// Composite ML-KEM (draft-ietf-lamps-pq-composite-kem), sub-arc 58.
    MlKem768X25519,
    /// Composite ML-KEM (draft-ietf-lamps-pq-composite-kem), sub-arc 59.
    MlKem768EcdhP256,
    /// Composite ML-KEM (draft-ietf-lamps-pq-composite-kem), sub-arc 63.
    MlKem1024EcdhP384,
}

impl KemAlgorithm {
    pub fn parameter_set_name(self) -> &'static str {
        match self {
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
            Self::MlKem768X25519 => "ML-KEM-768-X25519",
            Self::MlKem768EcdhP256 => "ML-KEM-768-ECDH-P256",
            Self::MlKem1024EcdhP384 => "ML-KEM-1024-ECDH-P384",
        }
    }

    /// Whether this is a composite ML-KEM variant (as opposed to pure ML-KEM).
    pub fn is_composite(self) -> bool {
        matches!(
            self,
            Self::MlKem768X25519 | Self::MlKem768EcdhP256 | Self::MlKem1024EcdhP384
        )
    }

    /// Composite OID sub-arc (58, 59, or 63) under
    /// `synta_certificate::oids::COMPOSITE_KEM_ARC`, or `None` for pure ML-KEM.
    pub fn composite_sub_arc(self) -> Option<u32> {
        match self {
            Self::MlKem768X25519 => Some(58),
            Self::MlKem768EcdhP256 => Some(59),
            Self::MlKem1024EcdhP384 => Some(63),
            _ => None,
        }
    }

    pub fn ciphertext_len(self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
            // Composite ciphertext = mlkemCT || tradCT (raw concatenation).
            Self::MlKem768X25519 => 1088 + 32,
            Self::MlKem768EcdhP256 => 1088 + 65,
            Self::MlKem1024EcdhP384 => 1568 + 97,
        }
    }

    pub fn encapsulation_key_len(self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
            // Composite public key = mlkemPK || tradPK (raw concatenation).
            Self::MlKem768X25519 => 1184 + 32,
            Self::MlKem768EcdhP256 => 1184 + 65,
            Self::MlKem1024EcdhP384 => 1568 + 97,
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
            Self::MlKem768X25519 => ID_MLKEM768_X25519_SHA3_256,
            Self::MlKem768EcdhP256 => ID_MLKEM768_ECDH_P256_SHA3_256,
            Self::MlKem1024EcdhP384 => ID_MLKEM1024_ECDH_P384_SHA3_256,
        }
    }

    pub fn from_oid(oid: &[u32]) -> Option<Self> {
        if oid == ID_ML_KEM_512 {
            Some(Self::MlKem512)
        } else if oid == ID_ML_KEM_768 {
            Some(Self::MlKem768)
        } else if oid == ID_ML_KEM_1024 {
            Some(Self::MlKem1024)
        } else if oid == ID_MLKEM768_X25519_SHA3_256 {
            Some(Self::MlKem768X25519)
        } else if oid == ID_MLKEM768_ECDH_P256_SHA3_256 {
            Some(Self::MlKem768EcdhP256)
        } else if oid == ID_MLKEM1024_ECDH_P384_SHA3_256 {
            Some(Self::MlKem1024EcdhP384)
        } else {
            None
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "ml-kem-512" | "mlkem512" => Some(Self::MlKem512),
            "ml-kem-768" | "mlkem768" => Some(Self::MlKem768),
            "ml-kem-1024" | "mlkem1024" => Some(Self::MlKem1024),
            "ml-kem-768-x25519" | "mlkem768-x25519" => Some(Self::MlKem768X25519),
            "ml-kem-768-ecdh-p256" | "mlkem768-ecdh-p256" => Some(Self::MlKem768EcdhP256),
            "ml-kem-1024-ecdh-p384" | "mlkem1024-ecdh-p384" => Some(Self::MlKem1024EcdhP384),
            _ => None,
        }
    }

    pub fn strength_order(self) -> u8 {
        match self {
            Self::MlKem512 => 1,
            Self::MlKem768 => 3,
            Self::MlKem1024 => 5,
            Self::MlKem768X25519 => 3,
            Self::MlKem768EcdhP256 => 3,
            Self::MlKem1024EcdhP384 => 5,
        }
    }

    /// Pure ML-KEM variants at or above this algorithm's NIST security
    /// category. Scoped to the pure ladder only — composite variants are
    /// explicit opt-in (`PkinitKdcConfig::supported_composite_kem_algorithms`)
    /// since a category-floor policy doesn't map cleanly onto them (each
    /// composite pairs a specific traditional algorithm, not just a strength).
    pub fn algorithms_at_or_above(self) -> Vec<Self> {
        let min = self.strength_order();
        [Self::MlKem512, Self::MlKem768, Self::MlKem1024]
            .into_iter()
            .filter(|a| a.strength_order() >= min)
            .collect()
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
pub use synta_certificate::oids::MLKEM768_ECDH_P256_SHA3_256 as ID_MLKEM768_ECDH_P256_SHA3_256;
pub use synta_certificate::oids::MLKEM768_X25519_SHA3_256 as ID_MLKEM768_X25519_SHA3_256;
pub use synta_certificate::oids::MLKEM1024_ECDH_P384_SHA3_256 as ID_MLKEM1024_ECDH_P384_SHA3_256;

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

// Kerberos PA-DATA type numbers (RFC 4120, RFC 6113, draft-bokovoy-kitten-pkinit-pqc)
pub const PA_PK_AS_REQ: i32 = 16;
pub const PA_PK_AS_REP: i32 = 17;
pub const PA_PKINIT_KX: i32 = 147;
pub const PA_AS_FRESHNESS: i32 = 150;

// Kerberos encryption type
pub const ENCTYPE_AES256_CTS_HMAC_SHA1_96: i32 = 18;

// KRB5_KEYUSAGE_PA_PKINIT_KX (RFC 6112)
pub const KRB5_KEYUSAGE_PA_PKINIT_KX: i32 = 44;

// MIT krb5 error code: KRB5_PREAUTH_FAILED
pub const KRB5_PREAUTH_FAILED: i32 = -1_765_328_174;

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
    fn kem_algorithm_from_name_roundtrip() {
        for alg in [
            KemAlgorithm::MlKem512,
            KemAlgorithm::MlKem768,
            KemAlgorithm::MlKem1024,
        ] {
            assert_eq!(KemAlgorithm::from_name(alg.parameter_set_name()), Some(alg));
        }
    }

    #[test]
    fn kem_algorithm_from_name_case_insensitive() {
        assert_eq!(
            KemAlgorithm::from_name("mlkem512"),
            Some(KemAlgorithm::MlKem512)
        );
        assert_eq!(
            KemAlgorithm::from_name("MLKEM768"),
            Some(KemAlgorithm::MlKem768)
        );
        assert_eq!(
            KemAlgorithm::from_name("Ml-Kem-1024"),
            Some(KemAlgorithm::MlKem1024)
        );
        assert_eq!(KemAlgorithm::from_name("unknown"), None);
    }

    #[test]
    fn kem_algorithm_strength_order() {
        assert!(KemAlgorithm::MlKem512.strength_order() < KemAlgorithm::MlKem768.strength_order());
        assert!(KemAlgorithm::MlKem768.strength_order() < KemAlgorithm::MlKem1024.strength_order());
    }

    #[test]
    fn kem_algorithms_at_or_above() {
        assert_eq!(
            KemAlgorithm::MlKem512.algorithms_at_or_above(),
            vec![
                KemAlgorithm::MlKem512,
                KemAlgorithm::MlKem768,
                KemAlgorithm::MlKem1024
            ]
        );
        assert_eq!(
            KemAlgorithm::MlKem768.algorithms_at_or_above(),
            vec![KemAlgorithm::MlKem768, KemAlgorithm::MlKem1024]
        );
        assert_eq!(
            KemAlgorithm::MlKem1024.algorithms_at_or_above(),
            vec![KemAlgorithm::MlKem1024]
        );
    }
}
