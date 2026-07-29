use synta_certificate::OpensslDecryptor;
use synta_x509_verification::{
    CrlStore, OwnedStore, PolicyDefinition, RevocationChecks, ValidationProfile,
    VerificationCertificate,
};

use crate::error::PkinitError;

pub struct TrustStore {
    anchors: Vec<Vec<u8>>,
    intermediates: Vec<Vec<u8>>,
    crls: Vec<Vec<u8>>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self {
            anchors: Vec::new(),
            intermediates: Vec::new(),
            crls: Vec::new(),
        }
    }

    pub fn add_anchor(&mut self, cert_der: Vec<u8>) {
        self.anchors.push(cert_der);
    }

    pub fn add_intermediate(&mut self, cert_der: Vec<u8>) {
        self.intermediates.push(cert_der);
    }

    pub fn add_crl(&mut self, crl_der: Vec<u8>) {
        self.crls.push(crl_der);
    }

    pub fn load_from_path(&mut self, uri: &str) -> Result<(), PkinitError> {
        let (scheme, path) = uri.split_once(':').unwrap_or(("FILE", uri));

        match scheme {
            "FILE" => {
                let data = std::fs::read(path)
                    .map_err(|e| PkinitError::IdentityLoadFailed(format!("reading {path}: {e}")))?;
                let blocks =
                    synta_certificate::read_pki_blocks(&data, b"", Some(&OpensslDecryptor))
                        .map_err(|e| {
                            PkinitError::IdentityLoadFailed(format!("parsing {path}: {e}"))
                        })?;
                for (label, der) in blocks {
                    match label.as_str() {
                        "CERTIFICATE" => self.anchors.push(der),
                        "X509 CRL" => self.crls.push(der),
                        _ => {}
                    }
                }
            }
            "DIR" => {
                let entries = std::fs::read_dir(path).map_err(|e| {
                    PkinitError::IdentityLoadFailed(format!("reading dir {path}: {e}"))
                })?;
                for entry in entries {
                    let entry = entry
                        .map_err(|e| PkinitError::IdentityLoadFailed(format!("dir entry: {e}")))?;
                    let file_path = entry.path();
                    if !file_path.is_file() {
                        continue;
                    }
                    let data = std::fs::read(&file_path).map_err(|e| {
                        PkinitError::IdentityLoadFailed(format!(
                            "reading {}: {e}",
                            file_path.display()
                        ))
                    })?;
                    if let Ok(blocks) =
                        synta_certificate::read_pki_blocks(&data, b"", Some(&OpensslDecryptor))
                    {
                        for (label, der) in blocks {
                            match label.as_str() {
                                "CERTIFICATE" => self.anchors.push(der),
                                "X509 CRL" => self.crls.push(der),
                                _ => {}
                            }
                        }
                    }
                }
            }
            _ => {
                return Err(PkinitError::Config(format!(
                    "unsupported trust store URI scheme: {scheme}"
                )));
            }
        }

        Ok(())
    }

    pub fn validate_chain(
        &self,
        cert_der: &[u8],
        chain: &[Vec<u8>],
        require_crl: bool,
    ) -> Result<(), PkinitError> {
        let store =
            OwnedStore::try_new(self.anchors.iter().map(|a| a.as_slice())).map_err(|e| {
                PkinitError::ChainValidationFailed(format!("building trust store: {e}"))
            })?;

        let leaf_cert: synta_certificate::Certificate<'_> =
            synta::Decoder::new(cert_der, synta::Encoding::Der)
                .decode()
                .map_err(|e| {
                    PkinitError::ChainValidationFailed(format!("decoding leaf cert: {e}"))
                })?;
        let leaf = VerificationCertificate::new(leaf_cert, cert_der);

        let all_intermediates: Vec<&[u8]> = chain
            .iter()
            .chain(self.intermediates.iter())
            .map(|v| v.as_slice())
            .collect();

        let mut intermediates_vc: Vec<VerificationCertificate<'_>> =
            Vec::with_capacity(all_intermediates.len());
        for int_der in &all_intermediates {
            let cert: synta_certificate::Certificate<'_> =
                synta::Decoder::new(int_der, synta::Encoding::Der)
                    .decode()
                    .map_err(|e| {
                        PkinitError::ChainValidationFailed(format!(
                            "decoding intermediate cert: {e}"
                        ))
                    })?;
            intermediates_vc.push(VerificationCertificate::new(cert, int_der));
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
        policy.ca_extension_policy = synta_x509_verification::ExtensionPolicy::new_permit_all();
        policy.ee_extension_policy = synta_x509_verification::ExtensionPolicy::new_permit_all();

        let revocation = if require_crl && !self.crls.is_empty() {
            let mut crl_store = CrlStore::new();
            for crl in &self.crls {
                crl_store.add_der(crl.clone());
            }
            Some(crl_store)
        } else {
            None
        };

        let rev_checks = RevocationChecks {
            crls: revocation.as_ref(),
            ocsp: None,
        };

        store
            .verify(&leaf, &intermediates_vc, &policy, rev_checks)
            .map_err(|e| PkinitError::ChainValidationFailed(e.to_string()))?;

        Ok(())
    }

    pub fn anchors(&self) -> &[Vec<u8>] {
        &self.anchors
    }
}

impl Default for TrustStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for TrustStore {
    fn clone(&self) -> Self {
        Self {
            anchors: self.anchors.clone(),
            intermediates: self.intermediates.clone(),
            crls: self.crls.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use native_ossl::pkey::{KeygenCtx, Pkey, Private};
    use synta::{Integer, UtcTime};
    use synta_certificate::{CertificateBuilder, NameBuilder, Time};

    fn generate_ec_key() -> Pkey<Private> {
        let params = native_ossl::params::ParamBuilder::new()
            .unwrap()
            .set(native_ossl::typed_params::ec::GROUP, c"P-256")
            .unwrap()
            .build()
            .unwrap();
        let mut kgen = KeygenCtx::new(c"EC").unwrap();
        kgen.set_params(&params).unwrap();
        kgen.generate().unwrap()
    }

    fn sign_cert(
        key: &Pkey<Private>,
        subject_name: &[u8],
        issuer_name: &[u8],
        subject_spki_der: &[u8],
        issuer_spki_der: &[u8],
        serial: i64,
        ca: bool,
    ) -> Vec<u8> {
        let pkcs8 = key.to_pkcs8_der().expect("PKCS#8 DER");
        let backend = synta_certificate::crypto::BackendPrivateKey::from_pkcs8_der_unchecked(pkcs8);
        let signer = synta_certificate::crypto::PrivateKey::as_signer(&backend, "sha256");

        let ski_der = synta_certificate::encode_subject_key_identifier(
            subject_spki_der,
            synta_certificate::KeyIdMethod::Rfc5280Sha1,
            &synta_certificate::OpensslKeyIdHasher,
        )
        .expect("SKI");
        let aki_der = synta_certificate::encode_authority_key_identifier(
            issuer_spki_der,
            synta_certificate::KeyIdMethod::Rfc5280Sha1,
            &synta_certificate::OpensslKeyIdHasher,
        )
        .expect("AKI");

        let mut builder = CertificateBuilder::new()
            .subject_name(subject_name)
            .issuer_name(issuer_name)
            .public_key_der(subject_spki_der)
            .serial_number(Integer::from_i64(serial))
            .not_valid_before(Time::UtcTime(UtcTime::new(2025, 1, 1, 0, 0, 0).unwrap()))
            .not_valid_after(Time::UtcTime(UtcTime::new(2027, 1, 1, 0, 0, 0).unwrap()))
            .add_extension_oid(
                synta_certificate::oids::SUBJECT_KEY_IDENTIFIER,
                false,
                &ski_der,
            )
            .add_extension_oid(
                synta_certificate::oids::AUTHORITY_KEY_IDENTIFIER,
                false,
                &aki_der,
            );

        if ca {
            let bc_der = synta_certificate::encode_basic_constraints(true, None).unwrap();
            builder = builder.add_extension_oid(
                synta_certificate::oids::BASIC_CONSTRAINTS,
                true,
                &bc_der,
            );
        }

        builder.sign(&signer).expect("sign cert")
    }

    #[test]
    fn trust_store_add_and_retrieve() {
        let mut store = TrustStore::new();
        store.add_anchor(vec![1, 2, 3]);
        store.add_intermediate(vec![4, 5, 6]);
        assert_eq!(store.anchors().len(), 1);
    }

    #[test]
    fn trust_store_default() {
        let store = TrustStore::default();
        assert!(store.anchors().is_empty());
    }

    #[test]
    fn trust_store_clone() {
        let mut store = TrustStore::new();
        store.add_anchor(vec![1, 2, 3]);
        let cloned = store.clone();
        assert_eq!(cloned.anchors().len(), 1);
    }

    #[test]
    fn validate_self_signed_chain() {
        let ca_key = generate_ec_key();
        let ca_spki = ca_key.public_key_to_der().unwrap();
        let ca_name = NameBuilder::new().common_name("Test CA").build().unwrap();

        let ca_cert_der = sign_cert(&ca_key, &ca_name, &ca_name, &ca_spki, &ca_spki, 1, true);

        let mut store = TrustStore::new();
        store.add_anchor(ca_cert_der.clone());

        store
            .validate_chain(&ca_cert_der, &[], false)
            .expect("self-signed CA should validate");
    }

    #[test]
    fn validate_two_cert_chain() {
        let ca_key = generate_ec_key();
        let ca_spki = ca_key.public_key_to_der().unwrap();
        let ca_name = NameBuilder::new().common_name("Test CA").build().unwrap();
        let ca_cert_der = sign_cert(&ca_key, &ca_name, &ca_name, &ca_spki, &ca_spki, 1, true);

        let ee_key = generate_ec_key();
        let ee_spki = ee_key.public_key_to_der().unwrap();
        let ee_name = NameBuilder::new().common_name("Test EE").build().unwrap();
        let ee_cert_der = sign_cert(&ca_key, &ee_name, &ca_name, &ee_spki, &ca_spki, 2, false);

        let mut store = TrustStore::new();
        store.add_anchor(ca_cert_der);

        store
            .validate_chain(&ee_cert_der, &[], false)
            .expect("EE cert signed by trusted CA should validate");
    }

    #[test]
    fn validate_untrusted_cert_fails() {
        let ca_key = generate_ec_key();
        let ca_spki = ca_key.public_key_to_der().unwrap();
        let ca_name = NameBuilder::new().common_name("Real CA").build().unwrap();
        let ca_cert_der = sign_cert(&ca_key, &ca_name, &ca_name, &ca_spki, &ca_spki, 1, true);

        let rogue_key = generate_ec_key();
        let rogue_spki = rogue_key.public_key_to_der().unwrap();
        let rogue_name = NameBuilder::new().common_name("Rogue CA").build().unwrap();
        let _rogue_cert_der = sign_cert(
            &rogue_key,
            &rogue_name,
            &rogue_name,
            &rogue_spki,
            &rogue_spki,
            1,
            true,
        );

        let ee_key = generate_ec_key();
        let ee_spki = ee_key.public_key_to_der().unwrap();
        let ee_name = NameBuilder::new().common_name("EE").build().unwrap();
        let ee_cert_der = sign_cert(
            &rogue_key,
            &ee_name,
            &rogue_name,
            &ee_spki,
            &rogue_spki,
            2,
            false,
        );

        let mut store = TrustStore::new();
        store.add_anchor(ca_cert_der);

        assert!(
            store.validate_chain(&ee_cert_der, &[], false).is_err(),
            "cert signed by untrusted CA should fail"
        );
    }

    #[test]
    fn load_from_file_path() {
        let ca_key = generate_ec_key();
        let ca_spki = ca_key.public_key_to_der().unwrap();
        let ca_name = NameBuilder::new().common_name("File CA").build().unwrap();
        let ca_cert_der = sign_cert(&ca_key, &ca_name, &ca_name, &ca_spki, &ca_spki, 1, true);

        let pem = synta_certificate::der_to_pem("CERTIFICATE", &ca_cert_der);

        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, &pem).unwrap();

        let mut store = TrustStore::new();
        store
            .load_from_path(&format!("FILE:{}", ca_path.display()))
            .unwrap();
        assert_eq!(store.anchors().len(), 1);
    }
}
