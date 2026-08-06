use std::path::Path;

use synta_certificate::OpensslDecryptor;

use crate::error::PkinitError;
use crate::identity::{IdentitySource, PkinitIdentity};

impl PkinitIdentity {
    pub fn load(source: &IdentitySource) -> Result<Self, PkinitError> {
        match source {
            IdentitySource::File {
                cert_path,
                key_path,
            } => Self::load_file(cert_path, key_path),
            IdentitySource::Dir { dir_path } => Self::load_dir(dir_path),
            IdentitySource::Pkcs12 { path } => Self::load_pkcs12(path, b""),
            IdentitySource::Pkcs11Uri { uri } => Self::load_pkcs11(uri),
            IdentitySource::Env { cert_var, key_var } => Self::load_env(cert_var, key_var),
        }
    }

    fn load_file(cert_path: &Path, key_path: &Path) -> Result<Self, PkinitError> {
        let cert_data = std::fs::read(cert_path).map_err(|e| {
            PkinitError::IdentityLoadFailed(format!("reading cert {}: {e}", cert_path.display()))
        })?;
        let key_data = std::fs::read(key_path).map_err(|e| {
            PkinitError::IdentityLoadFailed(format!("reading key {}: {e}", key_path.display()))
        })?;

        let cert_blocks =
            synta_certificate::read_pki_blocks(&cert_data, b"", Some(&OpensslDecryptor))
                .map_err(|e| PkinitError::IdentityLoadFailed(format!("parsing cert file: {e}")))?;

        let key_blocks =
            synta_certificate::read_pki_blocks(&key_data, b"", Some(&OpensslDecryptor))
                .map_err(|e| PkinitError::IdentityLoadFailed(format!("parsing key file: {e}")))?;

        let (cert_der, chain) = extract_cert_and_chain(&cert_blocks)?;
        let key_der = extract_private_key(&key_blocks)?;

        Ok(PkinitIdentity {
            cert_der,
            key_pkcs8_der: key_der,
            chain,
        })
    }

    fn load_dir(dir_path: &Path) -> Result<Self, PkinitError> {
        let mut all_blocks = Vec::new();
        let entries = std::fs::read_dir(dir_path).map_err(|e| {
            PkinitError::IdentityLoadFailed(format!(
                "reading directory {}: {e}",
                dir_path.display()
            ))
        })?;

        for entry in entries {
            let entry = entry
                .map_err(|e| PkinitError::IdentityLoadFailed(format!("reading dir entry: {e}")))?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let data = std::fs::read(&path).map_err(|e| {
                PkinitError::IdentityLoadFailed(format!("reading {}: {e}", path.display()))
            })?;
            if let Ok(blocks) =
                synta_certificate::read_pki_blocks(&data, b"", Some(&OpensslDecryptor))
            {
                all_blocks.extend(blocks);
            }
        }

        let (cert_der, chain) = extract_cert_and_chain(&all_blocks)?;
        let key_der = extract_private_key(&all_blocks)?;

        Ok(PkinitIdentity {
            cert_der,
            key_pkcs8_der: key_der,
            chain,
        })
    }

    pub fn load_pkcs12(path: &Path, password: &[u8]) -> Result<Self, PkinitError> {
        let data = std::fs::read(path).map_err(|e| {
            PkinitError::IdentityLoadFailed(format!("reading PKCS#12 {}: {e}", path.display()))
        })?;

        let pki = synta_certificate::pki_from_pkcs12(&data, password, &OpensslDecryptor).map_err(
            |e| match e {
                synta_certificate::Pkcs12Error::Crypto(_) => PkinitError::Pkcs12PasswordRequired,
                other => PkinitError::IdentityLoadFailed(format!("parsing PKCS#12: {other}")),
            },
        )?;

        let cert_der = pki
            .certs
            .first()
            .ok_or_else(|| {
                PkinitError::IdentityLoadFailed("PKCS#12 contains no certificates".into())
            })?
            .clone();

        let key_der = pki.keys.into_iter().next().ok_or_else(|| {
            PkinitError::IdentityLoadFailed("PKCS#12 contains no private keys".into())
        })?;

        let chain = pki.certs.into_iter().skip(1).collect();

        Ok(PkinitIdentity {
            cert_der,
            key_pkcs8_der: key_der,
            chain,
        })
    }

    fn load_pkcs11(_uri: &str) -> Result<Self, PkinitError> {
        // PKCS#11 key material stays on the hardware token and cannot be
        // exported as PKCS#8 DER.  The plugin adapter (kurbu5-pkinit) handles
        // PKCS#11 identities by keeping a BackendPrivateKey object for signing
        // and loading the certificate separately from the token.
        Err(PkinitError::Unsupported(
            "PKCS#11 identity loading requires the plugin adapter".into(),
        ))
    }

    fn load_env(cert_var: &str, key_var: &str) -> Result<Self, PkinitError> {
        let cert_path_str = std::env::var(cert_var).map_err(|e| {
            PkinitError::IdentityLoadFailed(format!("reading env var {cert_var}: {e}"))
        })?;
        let key_path_str = std::env::var(key_var).map_err(|e| {
            PkinitError::IdentityLoadFailed(format!("reading env var {key_var}: {e}"))
        })?;
        Self::load_file(Path::new(&cert_path_str), Path::new(&key_path_str))
    }
}

fn extract_cert_and_chain(
    blocks: &[(String, Vec<u8>)],
) -> Result<(Vec<u8>, Vec<Vec<u8>>), PkinitError> {
    let certs: Vec<&Vec<u8>> = blocks
        .iter()
        .filter(|(label, _)| label == "CERTIFICATE")
        .map(|(_, der)| der)
        .collect();

    let cert_der = certs
        .first()
        .ok_or_else(|| PkinitError::IdentityLoadFailed("no certificate found".into()))?;

    let chain = certs.iter().skip(1).map(|c| (*c).clone()).collect();

    Ok(((*cert_der).clone(), chain))
}

fn extract_private_key(blocks: &[(String, Vec<u8>)]) -> Result<Vec<u8>, PkinitError> {
    blocks
        .iter()
        .find(|(label, _)| label == "PRIVATE KEY" || label == "RSA PRIVATE KEY")
        .map(|(_, der)| der.clone())
        .ok_or_else(|| PkinitError::IdentityLoadFailed("no private key found".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use synta::{Integer, UtcTime};
    use synta_certificate::{
        CertificateBuilder, NameBuilder, OpensslPkcs12Encryptor, Pkcs12Builder, Time,
    };

    fn generate_test_cert_and_key() -> (Vec<u8>, Vec<u8>) {
        let ossl_pkey = {
            let params = native_ossl::params::ParamBuilder::new()
                .unwrap()
                .set(native_ossl::typed_params::ec::GROUP, c"P-256")
                .unwrap()
                .build()
                .unwrap();
            let mut kgen = native_ossl::pkey::KeygenCtx::new(c"EC").unwrap();
            kgen.set_params(&params).unwrap();
            kgen.generate().unwrap()
        };
        let pkcs8_der = ossl_pkey.to_pkcs8_der().unwrap();
        let spki_der = ossl_pkey.public_key_to_der().unwrap();

        let backend = synta_certificate::crypto::BackendPrivateKey::from_pkcs8_der_unchecked(
            pkcs8_der.clone(),
        );
        let signer = synta_certificate::crypto::PrivateKey::as_signer(&backend, "sha256");

        let name = NameBuilder::new()
            .common_name("Test Identity")
            .build()
            .expect("build name");

        let cert_der = CertificateBuilder::new()
            .subject_name(&name)
            .issuer_name(&name)
            .public_key_der(&spki_der)
            .serial_number(Integer::from_i64(1))
            .not_valid_before(Time::UtcTime(UtcTime::new(2025, 1, 1, 0, 0, 0).unwrap()))
            .not_valid_after(Time::UtcTime(UtcTime::new(2027, 1, 1, 0, 0, 0).unwrap()))
            .sign(&signer)
            .expect("sign cert");

        (cert_der, pkcs8_der)
    }

    #[test]
    fn load_file_identity() {
        let (cert_der, pkcs8_der) = generate_test_cert_and_key();

        let cert_pem = synta_certificate::der_to_pem("CERTIFICATE", &cert_der);
        let key_pem = synta_certificate::der_to_pem("PRIVATE KEY", &pkcs8_der);

        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();

        let source = IdentitySource::File {
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
        };
        let identity = PkinitIdentity::load(&source).unwrap();
        assert_eq!(identity.cert_der, cert_der);
        assert_eq!(identity.key_pkcs8_der, pkcs8_der);
        assert!(identity.chain.is_empty());
    }

    #[test]
    fn load_dir_identity() {
        let (cert_der, pkcs8_der) = generate_test_cert_and_key();

        let cert_pem = synta_certificate::der_to_pem("CERTIFICATE", &cert_der);
        let key_pem = synta_certificate::der_to_pem("PRIVATE KEY", &pkcs8_der);

        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("cert.pem"), &cert_pem).unwrap();
        std::fs::write(dir.path().join("key.pem"), &key_pem).unwrap();

        let source = IdentitySource::Dir {
            dir_path: dir.path().to_path_buf(),
        };
        let identity = PkinitIdentity::load(&source).unwrap();
        assert_eq!(identity.cert_der, cert_der);
        assert_eq!(identity.key_pkcs8_der, pkcs8_der);
    }

    #[test]
    fn load_file_missing_cert_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = IdentitySource::File {
            cert_path: dir.path().join("nonexistent.pem"),
            key_path: dir.path().join("key.pem"),
        };
        assert!(PkinitIdentity::load(&source).is_err());
    }

    #[test]
    fn load_env_missing_var_fails() {
        let source = IdentitySource::Env {
            cert_var: "PKINIT_TEST_NONEXISTENT_CERT_7291".to_string(),
            key_var: "PKINIT_TEST_NONEXISTENT_KEY_7291".to_string(),
        };
        assert!(PkinitIdentity::load(&source).is_err());
    }

    #[test]
    fn load_file_with_chain() {
        let (ca_cert_der, _) = generate_test_cert_and_key();
        let (ee_cert_der, ee_pkcs8_der) = generate_test_cert_and_key();

        let mut cert_pem = synta_certificate::der_to_pem("CERTIFICATE", &ee_cert_der);
        cert_pem.extend_from_slice(&synta_certificate::der_to_pem("CERTIFICATE", &ca_cert_der));
        let key_pem = synta_certificate::der_to_pem("PRIVATE KEY", &ee_pkcs8_der);

        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();

        let source = IdentitySource::File {
            cert_path,
            key_path,
        };
        let identity = PkinitIdentity::load(&source).unwrap();
        assert_eq!(identity.cert_der, ee_cert_der);
        assert_eq!(identity.chain.len(), 1);
        assert_eq!(identity.chain[0], ca_cert_der);
    }

    const TEST_PKCS12_PASSWORD: &[u8] = b"correct-horse-battery-staple";
    const TEST_PKCS12_WRONG_PASSWORD: &[u8] = b"wrong-password";

    fn make_test_pkcs12() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let (cert_der, pkcs8_der) = generate_test_cert_and_key();
        let pfx_der = Pkcs12Builder::new()
            .certificate(&cert_der)
            .private_key(&pkcs8_der)
            .build(TEST_PKCS12_PASSWORD, &OpensslPkcs12Encryptor::new())
            .expect("build PKCS#12");
        (pfx_der, cert_der, pkcs8_der)
    }

    #[test]
    fn load_pkcs12_wrong_password_requires_password() {
        let (pfx_der, _, _) = make_test_pkcs12();

        let dir = tempfile::tempdir().expect("tempdir");
        let p12_path = dir.path().join("identity.p12");
        std::fs::write(&p12_path, &pfx_der).unwrap();

        // `PkinitIdentity` deliberately doesn't implement `Debug` (it holds key
        // material), so `unwrap_err()` would fail to compile here; map the Ok
        // side away first.
        let err = PkinitIdentity::load_pkcs12(&p12_path, TEST_PKCS12_WRONG_PASSWORD)
            .map(|_| ())
            .unwrap_err();
        assert!(matches!(err, PkinitError::Pkcs12PasswordRequired));
    }

    #[test]
    fn load_pkcs12_correct_password_succeeds() {
        let (pfx_der, cert_der, pkcs8_der) = make_test_pkcs12();

        let dir = tempfile::tempdir().expect("tempdir");
        let p12_path = dir.path().join("identity.p12");
        std::fs::write(&p12_path, &pfx_der).unwrap();

        let identity = PkinitIdentity::load_pkcs12(&p12_path, TEST_PKCS12_PASSWORD).unwrap();
        assert_eq!(identity.cert_der, cert_der);
        assert_eq!(identity.key_pkcs8_der, pkcs8_der);
    }
}
