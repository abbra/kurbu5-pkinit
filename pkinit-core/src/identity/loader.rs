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
            signing_key: Some(
                synta_certificate::crypto::BackendPrivateKey::from_pkcs8_der_unchecked(key_der),
            ),
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
            signing_key: Some(
                synta_certificate::crypto::BackendPrivateKey::from_pkcs8_der_unchecked(key_der),
            ),
            chain,
        })
    }

    pub fn load_pkcs12(path: &Path, password: &[u8]) -> Result<Self, PkinitError> {
        let data = std::fs::read(path).map_err(|e| {
            PkinitError::IdentityLoadFailed(format!("reading PKCS#12 {}: {e}", path.display()))
        })?;

        let pki = synta_certificate::pki_from_pkcs12(&data, password, &OpensslDecryptor)
            .map_err(map_pkcs12_error)?;

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
            signing_key: Some(
                synta_certificate::crypto::BackendPrivateKey::from_pkcs8_der_unchecked(key_der),
            ),
            chain,
        })
    }

    fn load_pkcs11(uri: &str) -> Result<Self, PkinitError> {
        use synta_certificate::crypto::BackendPrivateKey;

        // The private key stays on the hardware token; we hold a live,
        // token-backed handle for signing.  It is never exported to PKCS#8.
        let signing_key = BackendPrivateKey::from_pkcs11_uri(uri).map_err(|e| {
            PkinitError::IdentityLoadFailed(format!(
                "loading PKCS#11 key from {}: {e}",
                redact_pkcs11_uri(uri)
            ))
        })?;

        // Read the certificate (and any additional chain certificates) from the
        // same token through the pkcs11-provider / OSSL_STORE path.  A URI that
        // selects the private key (`type=private`) would otherwise exclude the
        // certificate objects, so query with `type=cert`.
        let cert_uri = pkcs11_cert_uri(uri);
        let mut certs = synta_certificate::load_certs_from_pkcs11_uri(&cert_uri)
            .map_err(|e| {
                PkinitError::IdentityLoadFailed(format!(
                    "loading PKCS#11 certificate from {}: {e}",
                    redact_pkcs11_uri(&cert_uri)
                ))
            })?
            .into_iter();

        let cert_der = certs.next().ok_or_else(|| {
            PkinitError::IdentityLoadFailed(format!(
                "PKCS#11 token exposes no certificate for {}",
                redact_pkcs11_uri(uri)
            ))
        })?;
        let chain = certs.collect();

        Ok(PkinitIdentity {
            cert_der,
            signing_key: Some(signing_key),
            chain,
        })
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

/// Only an actual failed decrypt (wrong key, i.e. wrong password) should
/// trigger a responder retry with a different password. `UnsupportedAlgorithm`
/// means the archive uses a cipher this build doesn't implement (e.g. legacy
/// RC2-40-CBC) — no password would ever fix that, so it must not be conflated
/// with `Pkcs12PasswordRequired`.
fn map_pkcs12_error(
    e: synta_certificate::Pkcs12Error<synta_certificate::OpensslDecryptorError>,
) -> PkinitError {
    match e {
        synta_certificate::Pkcs12Error::Crypto(
            synta_certificate::OpensslDecryptorError::Openssl(_),
        ) => PkinitError::Pkcs12PasswordRequired,
        other => PkinitError::IdentityLoadFailed(format!("parsing PKCS#12: {other}")),
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

/// Derive a certificate-selecting PKCS#11 URI from an identity URI.
///
/// An identity URI often pins the private key with `type=private`; reusing it
/// verbatim to read certificates would match nothing.  This strips any existing
/// `type=` path attribute and appends `type=cert`, preserving every other path
/// attribute (`token`, `object`, `id`, `module-path`, ...) and the query
/// component (which carries `pin-value`).
/// Strip the query component from a PKCS#11 URI before it appears in any
/// user-facing message.  The query may carry `pin-value=<PIN>`, which must
/// never be logged.
fn redact_pkcs11_uri(uri: &str) -> &str {
    uri.split_once('?').map_or(uri, |(path, _)| path)
}

fn pkcs11_cert_uri(uri: &str) -> String {
    let (path, query) = match uri.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (uri, None),
    };

    let mut components: Vec<&str> = path
        .split(';')
        .filter(|c| !c.starts_with("type="))
        .collect();
    // The first component is the `pkcs11:` scheme (plus any leading attribute);
    // append the cert type selector as a new attribute.
    let type_cert = "type=cert";
    components.push(type_cert);
    let mut out = components.join(";");
    if let Some(q) = query {
        out.push('?');
        out.push_str(q);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::test_validity;
    use synta::Integer;
    use synta_certificate::crypto::PrivateKey;
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

        let (nb, na) = test_validity().expect("validity window");
        let cert_der = CertificateBuilder::new()
            .subject_name(&name)
            .issuer_name(&name)
            .public_key_der(&spki_der)
            .serial_number(Integer::from_i64(1))
            .not_valid_before(Time::UtcTime(nb))
            .not_valid_after(Time::UtcTime(na))
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
        // The private key is no longer stored as raw PKCS#8; confirm the loaded
        // signing key matches the expected key by comparing public keys.
        let got_spki = identity
            .signing_key
            .as_ref()
            .unwrap()
            .public_key_spki_der()
            .unwrap();
        let want_spki = synta_certificate::crypto::BackendPrivateKey::from_pkcs8_der_unchecked(
            pkcs8_der.clone(),
        )
        .public_key_spki_der()
        .unwrap();
        assert_eq!(got_spki, want_spki);
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
        // The private key is no longer stored as raw PKCS#8; confirm the loaded
        // signing key matches the expected key by comparing public keys.
        let got_spki = identity
            .signing_key
            .as_ref()
            .unwrap()
            .public_key_spki_der()
            .unwrap();
        let want_spki = synta_certificate::crypto::BackendPrivateKey::from_pkcs8_der_unchecked(
            pkcs8_der.clone(),
        )
        .public_key_spki_der()
        .unwrap();
        assert_eq!(got_spki, want_spki);
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
    fn pkcs11_cert_uri_replaces_type_private_with_cert() {
        assert_eq!(
            pkcs11_cert_uri("pkcs11:token=MyToken;object=cakey;type=private"),
            "pkcs11:token=MyToken;object=cakey;type=cert"
        );
    }

    #[test]
    fn pkcs11_cert_uri_appends_type_when_absent() {
        assert_eq!(
            pkcs11_cert_uri("pkcs11:token=MyToken;object=cakey"),
            "pkcs11:token=MyToken;object=cakey;type=cert"
        );
    }

    #[test]
    fn redact_pkcs11_uri_strips_pin_value() {
        assert_eq!(
            redact_pkcs11_uri("pkcs11:token=MyToken;object=cakey?pin-value=1234"),
            "pkcs11:token=MyToken;object=cakey"
        );
        assert_eq!(
            redact_pkcs11_uri("pkcs11:token=MyToken;object=cakey"),
            "pkcs11:token=MyToken;object=cakey"
        );
    }

    #[test]
    fn pkcs11_cert_uri_preserves_pin_query() {
        assert_eq!(
            pkcs11_cert_uri("pkcs11:token=MyToken;object=cakey;type=private?pin-value=1234"),
            "pkcs11:token=MyToken;object=cakey;type=cert?pin-value=1234"
        );
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
        // The private key is no longer stored as raw PKCS#8; confirm the loaded
        // signing key matches the expected key by comparing public keys.
        let got_spki = identity
            .signing_key
            .as_ref()
            .unwrap()
            .public_key_spki_der()
            .unwrap();
        let want_spki = synta_certificate::crypto::BackendPrivateKey::from_pkcs8_der_unchecked(
            pkcs8_der.clone(),
        )
        .public_key_spki_der()
        .unwrap();
        assert_eq!(got_spki, want_spki);
    }

    #[test]
    fn unsupported_pkcs12_algorithm_is_not_a_password_prompt() {
        // A legacy cipher this build doesn't implement (e.g. RC2-40-CBC, still
        // common in PKCS#12 files produced by older tools) must not be
        // reported as "needs a password" -- no password would ever fix it.
        let err = map_pkcs12_error(synta_certificate::Pkcs12Error::Crypto(
            synta_certificate::OpensslDecryptorError::UnsupportedAlgorithm(
                "pbeWithSHA1And40BitRC2-CBC".into(),
            ),
        ));
        assert!(matches!(err, PkinitError::IdentityLoadFailed(_)));
    }
}
