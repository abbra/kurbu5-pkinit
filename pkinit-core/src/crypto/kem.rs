use crate::constants::KemAlgorithm;
use crate::error::PkinitError;
use synta_certificate::crypto::{BackendPrivateKey, BackendPublicKey, PrivateKey};

pub struct KemKeyPair {
    algorithm: KemAlgorithm,
    private_key: BackendPrivateKey,
}

impl KemKeyPair {
    pub fn generate(algorithm: KemAlgorithm) -> Result<Self, PkinitError> {
        let private_key = if let Some(sub_arc) = algorithm.composite_sub_arc() {
            BackendPrivateKey::generate_composite_kem(sub_arc)
        } else {
            BackendPrivateKey::generate_ml_kem(algorithm.parameter_set_name())
        }
        .map_err(|e| {
            PkinitError::KemEncapFailed(format!("generate {}: {e}", algorithm.parameter_set_name()))
        })?;
        Ok(Self {
            algorithm,
            private_key,
        })
    }

    pub fn public_key_spki_der(&self) -> Result<Vec<u8>, PkinitError> {
        self.private_key
            .public_key_spki_der()
            .map_err(|e| PkinitError::KemEncapFailed(format!("SPKI export: {e}")))
    }

    pub fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }

    /// Decapsulate a KEM ciphertext to recover the shared secret.
    ///
    /// Takes `self` by value to ensure the private key is erased after use.
    pub fn decapsulate(
        self,
        ciphertext: &[u8],
    ) -> Result<native_ossl::util::SecretBuf, PkinitError> {
        if ciphertext.len() != self.algorithm.ciphertext_len() {
            return Err(PkinitError::KemCiphertextLengthInvalid {
                expected: self.algorithm.ciphertext_len(),
                actual: ciphertext.len(),
            });
        }
        let result = if self.algorithm.is_composite() {
            self.private_key.composite_kem_decapsulate(ciphertext)
        } else {
            self.private_key.ml_kem_decapsulate(ciphertext)
        };
        result
            .map(native_ossl::util::SecretBuf::new)
            .map_err(|e| PkinitError::KemDecapFailed(format!("{e}")))
    }
}

/// Encapsulate against a client's ML-KEM public key.
///
/// Returns `(ciphertext, shared_secret)`.
pub fn encapsulate_for_client(
    client_spki_der: &[u8],
    algorithm: KemAlgorithm,
) -> Result<(Vec<u8>, native_ossl::util::SecretBuf), PkinitError> {
    let pub_key = BackendPublicKey::from_spki_der(client_spki_der.to_vec());
    let (ciphertext, shared_secret) = if algorithm.is_composite() {
        pub_key.composite_kem_encapsulate()
    } else {
        pub_key.ml_kem_encapsulate()
    }
    .map_err(|e| {
        PkinitError::KemEncapFailed(format!(
            "encapsulate {}: {e}",
            algorithm.parameter_set_name()
        ))
    })?;

    if ciphertext.len() != algorithm.ciphertext_len() {
        return Err(PkinitError::KemCiphertextLengthInvalid {
            expected: algorithm.ciphertext_len(),
            actual: ciphertext.len(),
        });
    }

    Ok((ciphertext, native_ossl::util::SecretBuf::new(shared_secret)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_keygen_mlkem768() {
        let kp = KemKeyPair::generate(KemAlgorithm::MlKem768).unwrap();
        assert_eq!(kp.algorithm(), KemAlgorithm::MlKem768);
        let spki = kp.public_key_spki_der().unwrap();
        assert!(!spki.is_empty());
    }

    #[test]
    fn kem_roundtrip_mlkem768() {
        let kp = KemKeyPair::generate(KemAlgorithm::MlKem768).unwrap();
        let spki = kp.public_key_spki_der().unwrap();

        let (ciphertext, shared_secret) =
            encapsulate_for_client(&spki, KemAlgorithm::MlKem768).unwrap();
        assert_eq!(ciphertext.len(), KemAlgorithm::MlKem768.ciphertext_len());
        assert_eq!(
            shared_secret.as_ref().len(),
            KemAlgorithm::MlKem768.shared_secret_len()
        );

        let recovered = kp.decapsulate(&ciphertext).unwrap();
        assert_eq!(recovered.as_ref(), shared_secret.as_ref());
    }

    #[test]
    fn kem_roundtrip_mlkem512() {
        let kp = KemKeyPair::generate(KemAlgorithm::MlKem512).unwrap();
        let spki = kp.public_key_spki_der().unwrap();

        let (ct, ss) = encapsulate_for_client(&spki, KemAlgorithm::MlKem512).unwrap();
        assert_eq!(ct.len(), KemAlgorithm::MlKem512.ciphertext_len());
        assert_eq!(ss.as_ref().len(), 32);

        let recovered = kp.decapsulate(&ct).unwrap();
        assert_eq!(recovered.as_ref(), ss.as_ref());
    }

    #[test]
    fn kem_roundtrip_mlkem1024() {
        let kp = KemKeyPair::generate(KemAlgorithm::MlKem1024).unwrap();
        let spki = kp.public_key_spki_der().unwrap();

        let (ct, ss) = encapsulate_for_client(&spki, KemAlgorithm::MlKem1024).unwrap();
        assert_eq!(ct.len(), KemAlgorithm::MlKem1024.ciphertext_len());

        let recovered = kp.decapsulate(&ct).unwrap();
        assert_eq!(recovered.as_ref(), ss.as_ref());
    }

    #[test]
    fn kem_roundtrip_composite_mlkem768_x25519() {
        let kp = KemKeyPair::generate(KemAlgorithm::MlKem768X25519).unwrap();
        let spki = kp.public_key_spki_der().unwrap();

        let (ct, ss) = encapsulate_for_client(&spki, KemAlgorithm::MlKem768X25519).unwrap();
        assert_eq!(ct.len(), KemAlgorithm::MlKem768X25519.ciphertext_len());
        assert_eq!(ss.as_ref().len(), 32);

        let recovered = kp.decapsulate(&ct).unwrap();
        assert_eq!(recovered.as_ref(), ss.as_ref());
    }

    #[test]
    fn kem_roundtrip_composite_mlkem768_ecdh_p256() {
        let kp = KemKeyPair::generate(KemAlgorithm::MlKem768EcdhP256).unwrap();
        let spki = kp.public_key_spki_der().unwrap();

        let (ct, ss) = encapsulate_for_client(&spki, KemAlgorithm::MlKem768EcdhP256).unwrap();
        assert_eq!(ct.len(), KemAlgorithm::MlKem768EcdhP256.ciphertext_len());
        assert_eq!(ss.as_ref().len(), 32);

        let recovered = kp.decapsulate(&ct).unwrap();
        assert_eq!(recovered.as_ref(), ss.as_ref());
    }

    #[test]
    fn kem_roundtrip_composite_mlkem1024_ecdh_p384() {
        let kp = KemKeyPair::generate(KemAlgorithm::MlKem1024EcdhP384).unwrap();
        let spki = kp.public_key_spki_der().unwrap();

        let (ct, ss) = encapsulate_for_client(&spki, KemAlgorithm::MlKem1024EcdhP384).unwrap();
        assert_eq!(ct.len(), KemAlgorithm::MlKem1024EcdhP384.ciphertext_len());
        assert_eq!(ss.as_ref().len(), 32);

        let recovered = kp.decapsulate(&ct).unwrap();
        assert_eq!(recovered.as_ref(), ss.as_ref());
    }

    #[test]
    fn kem_decap_rejects_wrong_ciphertext_length() {
        let kp = KemKeyPair::generate(KemAlgorithm::MlKem768).unwrap();
        match kp.decapsulate(&[0u8; 100]) {
            Err(PkinitError::KemCiphertextLengthInvalid { expected, actual }) => {
                assert_eq!(expected, 1088);
                assert_eq!(actual, 100);
            }
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("expected error for wrong ciphertext length"),
        }
    }

    #[test]
    fn kem_different_keypairs_produce_different_secrets() {
        let kp1 = KemKeyPair::generate(KemAlgorithm::MlKem768).unwrap();
        let kp2 = KemKeyPair::generate(KemAlgorithm::MlKem768).unwrap();
        let spki1 = kp1.public_key_spki_der().unwrap();
        let spki2 = kp2.public_key_spki_der().unwrap();
        assert_ne!(spki1, spki2);
    }
}
