use pkinit_core::client::PkinitClientState;
use pkinit_core::config::{PkinitClientConfig, PkinitKdcConfig};
use pkinit_core::constants::{self, DhGroup, KemAlgorithm};
use pkinit_core::crypto::kdf::OctetString2Key;
use pkinit_core::error::PkinitError;
use pkinit_core::identity::{PkinitIdentity, TrustStore};
use pkinit_core::server::{BuildAsRepParams, PkinitKdcState};
use pkinit_core::test_support::next_nonce;
use synta_certificate::crypto::{BackendPrivateKey, PrivateKey};

struct TestO2K;

impl OctetString2Key for TestO2K {
    fn random_to_key(
        &self,
        enctype: i32,
        random_data: &[u8],
    ) -> Result<native_ossl::util::SecretBuf, PkinitError> {
        let len = self.key_length(enctype)?;
        let mut key = random_data.to_vec();
        key.resize(len, 0);
        Ok(native_ossl::util::SecretBuf::new(key[..len].to_vec()))
    }

    fn random_length(&self, enctype: i32) -> Result<usize, PkinitError> {
        self.key_length(enctype)
    }

    fn key_length(&self, enctype: i32) -> Result<usize, PkinitError> {
        match enctype {
            17 => Ok(16),
            18 => Ok(32),
            _ => Err(PkinitError::Unsupported(format!("enctype {enctype}"))),
        }
    }
}

#[derive(Clone, Copy)]
enum TestKeyType {
    EcP256,
    EcP384,
    EcP521,
    Rsa2048,
}

fn generate_key(key_type: TestKeyType) -> BackendPrivateKey {
    match key_type {
        TestKeyType::EcP256 => BackendPrivateKey::generate_ec("P-256").unwrap(),
        TestKeyType::EcP384 => BackendPrivateKey::generate_ec("P-384").unwrap(),
        TestKeyType::EcP521 => BackendPrivateKey::generate_ec("P-521").unwrap(),
        TestKeyType::Rsa2048 => BackendPrivateKey::generate_rsa(2048, 65537).unwrap(),
    }
}

fn generate_test_pki(key_type: TestKeyType) -> (PkinitIdentity, PkinitIdentity, TrustStore) {
    use synta::{Integer, UtcTime};
    use synta_certificate::{
        CertificateBuilder, ExtendedKeyUsageBuilder, NameBuilder, SubjectAlternativeNameBuilder,
        Time,
    };

    let ca_key = generate_key(key_type);
    let ca_pkcs8 = ca_key.to_der().unwrap();
    let ca_spki = ca_key.public_key_spki_der().unwrap();
    let ca_name = NameBuilder::new()
        .common_name("Test PKINIT CA")
        .build()
        .unwrap();

    let ca_backend = BackendPrivateKey::from_pkcs8_der_unchecked(ca_pkcs8);
    let ca_signer = synta_certificate::crypto::PrivateKey::as_signer(&ca_backend, "sha256");

    let ski_der = synta_certificate::encode_subject_key_identifier(
        &ca_spki,
        synta_certificate::KeyIdMethod::Rfc5280Sha1,
        &synta_certificate::OpensslKeyIdHasher,
    )
    .unwrap();
    let aki_der = synta_certificate::encode_authority_key_identifier(
        &ca_spki,
        synta_certificate::KeyIdMethod::Rfc5280Sha1,
        &synta_certificate::OpensslKeyIdHasher,
    )
    .unwrap();
    let bc_der = synta_certificate::encode_basic_constraints(true, None).unwrap();

    let ca_cert_der = CertificateBuilder::new()
        .subject_name(&ca_name)
        .issuer_name(&ca_name)
        .public_key_der(&ca_spki)
        .serial_number(Integer::from_i64(1))
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
        )
        .add_extension_oid(synta_certificate::oids::BASIC_CONSTRAINTS, true, &bc_der)
        .sign(&ca_signer)
        .unwrap();

    let make_identity =
        |cn: &str, san_oid_data: Vec<u8>, eku_oid: &[u32], serial: i64| -> PkinitIdentity {
            let ee_key = generate_key(key_type);
            let pkcs8 = ee_key.to_der().unwrap();
            let spki = ee_key.public_key_spki_der().unwrap();
            let name = NameBuilder::new().common_name(cn).build().unwrap();

            let san_der = SubjectAlternativeNameBuilder::new()
                .other_name(&san_oid_data)
                .build()
                .unwrap();
            let eku_der = ExtendedKeyUsageBuilder::new()
                .add_oid(eku_oid)
                .build()
                .unwrap();
            let ku_der = synta_certificate::encode_key_usage(
                1 << synta_certificate::KEY_USAGE_DIGITAL_SIGNATURE,
            )
            .unwrap();

            let ee_ski = synta_certificate::encode_subject_key_identifier(
                &spki,
                synta_certificate::KeyIdMethod::Rfc5280Sha1,
                &synta_certificate::OpensslKeyIdHasher,
            )
            .unwrap();
            let ee_aki = synta_certificate::encode_authority_key_identifier(
                &ca_spki,
                synta_certificate::KeyIdMethod::Rfc5280Sha1,
                &synta_certificate::OpensslKeyIdHasher,
            )
            .unwrap();

            let cert_der = CertificateBuilder::new()
                .subject_name(&name)
                .issuer_name(&ca_name)
                .public_key_der(&spki)
                .serial_number(Integer::from_i64(serial))
                .not_valid_before(Time::UtcTime(UtcTime::new(2025, 1, 1, 0, 0, 0).unwrap()))
                .not_valid_after(Time::UtcTime(UtcTime::new(2027, 1, 1, 0, 0, 0).unwrap()))
                .add_extension_oid(synta_certificate::oids::SUBJECT_ALT_NAME, false, &san_der)
                .add_extension_oid(synta_certificate::oids::EXTENDED_KEY_USAGE, false, &eku_der)
                .add_extension_oid(synta_certificate::oids::KEY_USAGE, true, &ku_der)
                .add_extension_oid(
                    synta_certificate::oids::SUBJECT_KEY_IDENTIFIER,
                    false,
                    &ee_ski,
                )
                .add_extension_oid(
                    synta_certificate::oids::AUTHORITY_KEY_IDENTIFIER,
                    false,
                    &ee_aki,
                )
                .sign(&ca_signer)
                .unwrap();

            PkinitIdentity {
                cert_der,
                key_pkcs8_der: pkcs8,
                chain: vec![ca_cert_der.clone()],
            }
        };

    let client_san = synta_krb5::principal::encode_krb5_san("testuser", "EXAMPLE.COM").unwrap();
    let client_id = make_identity(
        "Test Client",
        client_san,
        constants::ID_PKINIT_KPCLIENT_AUTH,
        2,
    );

    let kdc_san =
        synta_krb5::principal::encode_krb5_san("krbtgt/EXAMPLE.COM", "EXAMPLE.COM").unwrap();
    let kdc_id = make_identity("Test KDC", kdc_san, constants::ID_PKINIT_KPKDC, 3);

    let mut trust_store = TrustStore::new();
    trust_store.add_anchor(ca_cert_der);

    (client_id, kdc_id, trust_store)
}

fn run_dh_exchange(key_type: TestKeyType, dh_group: DhGroup, enctype: i32) {
    let (client_id, kdc_id, trust_store) = generate_test_pki(key_type);
    let o2k = TestO2K;

    let client_config = PkinitClientConfig {
        dh_group,
        ..Default::default()
    };
    let mut client = PkinitClientState::new(client_id, trust_store.clone(), client_config);
    client.set_kdc_identity("krbtgt/EXAMPLE.COM@EXAMPLE.COM".to_string(), None);

    let server = PkinitKdcState::new(kdc_id, trust_store, PkinitKdcConfig::default()).unwrap();

    let req_body_der = b"test-kdc-req-body";
    let nonce = next_nonce();
    let ctime = 1719600000i64;

    let pa_req = client.build_as_req(nonce, ctime, 0, req_body_der).unwrap();

    let verified = server
        .verify_as_req(&pa_req, Some(req_body_der), 300, ctime)
        .unwrap();
    assert!(!verified.is_anonymous);

    let as_req_full = b"test-full-as-req";
    let client_name = "testuser@EXAMPLE.COM";
    let server_name = "krbtgt/EXAMPLE.COM@EXAMPLE.COM";
    let (pa_rep, server_key) = server
        .build_as_rep(
            &verified,
            &BuildAsRepParams {
                nonce,
                enctype,
                as_req_der: as_req_full,
                client_name,
                server_name,
            },
            &o2k,
        )
        .unwrap();

    let client_key = client
        .process_as_rep(
            &pa_rep,
            &pkinit_core::client::AsRepParams {
                nonce,
                enctype,
                as_req_der: as_req_full,
                pa_rep_raw: &pa_rep,
                client_name,
                server_name,
            },
            &o2k,
        )
        .unwrap();

    assert_eq!(client_key.enctype, server_key.enctype);
    assert_eq!(client_key.key_data.as_ref(), server_key.key_data.as_ref());
    assert_eq!(client_key.enctype, enctype);
    assert!(!client_key.key_data.as_ref().is_empty());
}

fn run_anonymous_exchange(dh_group: DhGroup) {
    let (_, kdc_id, trust_store) = generate_test_pki(TestKeyType::EcP256);
    let o2k = TestO2K;

    let anon_identity = PkinitIdentity {
        cert_der: vec![],
        key_pkcs8_der: vec![],
        chain: vec![],
    };

    let client_config = PkinitClientConfig {
        dh_group,
        ..Default::default()
    };
    let mut client = PkinitClientState::new(anon_identity, trust_store.clone(), client_config);
    client.set_kdc_identity("krbtgt/EXAMPLE.COM@EXAMPLE.COM".to_string(), None);

    let server = PkinitKdcState::new(kdc_id, trust_store, PkinitKdcConfig::default()).unwrap();

    let req_body_der = b"anon-req-body";
    let nonce = next_nonce();
    let enctype = 18;
    let ctime = 1719600000i64;

    let pa_req = client.build_as_req(nonce, ctime, 0, req_body_der).unwrap();

    let verified = server
        .verify_as_req(&pa_req, Some(req_body_der), 300, ctime)
        .unwrap();
    assert!(verified.is_anonymous);

    let as_req_full = b"anon-full-as-req";
    let client_name = "WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS";
    let server_name = "krbtgt/EXAMPLE.COM@EXAMPLE.COM";
    let (pa_rep, server_key) = server
        .build_as_rep(
            &verified,
            &BuildAsRepParams {
                nonce,
                enctype,
                as_req_der: as_req_full,
                client_name,
                server_name,
            },
            &o2k,
        )
        .unwrap();

    let client_key = client
        .process_as_rep(
            &pa_rep,
            &pkinit_core::client::AsRepParams {
                nonce,
                enctype,
                as_req_der: as_req_full,
                pa_rep_raw: &pa_rep,
                client_name,
                server_name,
            },
            &o2k,
        )
        .unwrap();

    assert_eq!(client_key.key_data.as_ref(), server_key.key_data.as_ref());
    assert_eq!(client_key.enctype, enctype);
}

// --- EC P-256 (existing coverage) ---

#[test]
fn pkinit_dh_full_exchange_aes256() {
    run_dh_exchange(TestKeyType::EcP256, DhGroup::EcP256, 18);
}

#[test]
fn pkinit_dh_full_exchange_aes128() {
    run_dh_exchange(TestKeyType::EcP256, DhGroup::EcP256, 17);
}

#[test]
fn pkinit_anonymous_exchange() {
    run_anonymous_exchange(DhGroup::EcP256);
}

// --- RSA-2048 certificates ---

#[test]
fn pkinit_dh_rsa2048_exchange() {
    run_dh_exchange(TestKeyType::Rsa2048, DhGroup::EcP256, 18);
}

#[test]
fn pkinit_dh_rsa_oakley2048_exchange() {
    run_dh_exchange(TestKeyType::Rsa2048, DhGroup::Oakley2048, 18);
}

// --- EC P-384 certificates ---

#[test]
fn pkinit_dh_ec_p384_exchange() {
    run_dh_exchange(TestKeyType::EcP384, DhGroup::EcP384, 18);
}

// --- EC P-521 certificates ---

#[test]
fn pkinit_dh_ec_p521_exchange() {
    run_dh_exchange(TestKeyType::EcP521, DhGroup::EcP521, 18);
}

// --- Cross-type: EC P-256 cert with Oakley4096 DH ---

#[test]
fn pkinit_dh_oakley4096_exchange() {
    run_dh_exchange(TestKeyType::EcP256, DhGroup::Oakley4096, 18);
}

// --- KEM exchange tests ---

fn run_kem_exchange(kem_alg: KemAlgorithm, enctype: i32) {
    let (client_id, kdc_id, trust_store) = generate_test_pki(TestKeyType::EcP256);
    let o2k = TestO2K;

    let client_config = PkinitClientConfig {
        kem_algorithm: Some(kem_alg),
        ..Default::default()
    };
    let mut client = PkinitClientState::new(client_id, trust_store.clone(), client_config);
    client.set_kdc_identity("krbtgt/EXAMPLE.COM@EXAMPLE.COM".to_string(), None);

    let server = PkinitKdcState::new(kdc_id, trust_store, PkinitKdcConfig::default()).unwrap();

    let req_body_der = b"test-kem-req-body";
    let nonce = next_nonce();
    let ctime = 1719600000i64;

    let pa_req = client.build_as_req(nonce, ctime, 0, req_body_der).unwrap();

    let verified = server
        .verify_as_req(&pa_req, Some(req_body_der), 300, ctime)
        .unwrap();
    assert!(!verified.is_anonymous);
    assert!(matches!(
        verified.key_exchange,
        pkinit_core::server::KeyExchangeType::Kem(_)
    ));

    let as_req_full = b"test-kem-full-as-req";
    let client_name = "testuser@EXAMPLE.COM";
    let server_name = "krbtgt/EXAMPLE.COM@EXAMPLE.COM";
    let (pa_rep, server_key) = server
        .build_as_rep(
            &verified,
            &BuildAsRepParams {
                nonce,
                enctype,
                as_req_der: as_req_full,
                client_name,
                server_name,
            },
            &o2k,
        )
        .unwrap();

    assert!(pkinit_core::kem_types::is_kem_rep(&pa_rep));

    let client_key = client
        .process_as_rep(
            &pa_rep,
            &pkinit_core::client::AsRepParams {
                nonce,
                enctype,
                as_req_der: as_req_full,
                pa_rep_raw: &pa_rep,
                client_name,
                server_name,
            },
            &o2k,
        )
        .unwrap();

    assert_eq!(client_key.enctype, server_key.enctype);
    assert_eq!(client_key.key_data.as_ref(), server_key.key_data.as_ref());
    assert_eq!(client_key.enctype, enctype);
    assert!(!client_key.key_data.as_ref().is_empty());
}

#[test]
fn pkinit_kem_mlkem768_exchange() {
    run_kem_exchange(KemAlgorithm::MlKem768, 18);
}

#[test]
fn pkinit_kem_mlkem1024_exchange() {
    run_kem_exchange(KemAlgorithm::MlKem1024, 18);
}

#[test]
fn pkinit_kem_mlkem512_exchange() {
    run_kem_exchange(KemAlgorithm::MlKem512, 17);
}

// --- Composite ML-KEM exchange tests (draft-ietf-lamps-pq-composite-kem) ---
//
// Composite algorithms are explicit opt-in on the KDC side (unlike pure
// ML-KEM's permissive empty-list default), so these need their own KDC config.

fn run_composite_kem_exchange(kem_alg: KemAlgorithm, enctype: i32) {
    let (client_id, kdc_id, trust_store) = generate_test_pki(TestKeyType::EcP256);
    let o2k = TestO2K;

    let client_config = PkinitClientConfig {
        kem_algorithm: Some(kem_alg),
        ..Default::default()
    };
    let mut client = PkinitClientState::new(client_id, trust_store.clone(), client_config);
    client.set_kdc_identity("krbtgt/EXAMPLE.COM@EXAMPLE.COM".to_string(), None);

    let kdc_config = PkinitKdcConfig {
        supported_composite_kem_algorithms: vec![kem_alg],
        ..Default::default()
    };
    let server = PkinitKdcState::new(kdc_id, trust_store, kdc_config).unwrap();

    let req_body_der = b"test-composite-kem-req-body";
    let nonce = next_nonce();
    let ctime = 1719600000i64;

    let pa_req = client.build_as_req(nonce, ctime, 0, req_body_der).unwrap();

    let verified = server
        .verify_as_req(&pa_req, Some(req_body_der), 300, ctime)
        .unwrap();
    assert!(!verified.is_anonymous);
    assert!(matches!(
        verified.key_exchange,
        pkinit_core::server::KeyExchangeType::Kem(_)
    ));

    let as_req_full = b"test-composite-kem-full-as-req";
    let client_name = "testuser@EXAMPLE.COM";
    let server_name = "krbtgt/EXAMPLE.COM@EXAMPLE.COM";
    let (pa_rep, server_key) = server
        .build_as_rep(
            &verified,
            &BuildAsRepParams {
                nonce,
                enctype,
                as_req_der: as_req_full,
                client_name,
                server_name,
            },
            &o2k,
        )
        .unwrap();

    assert!(pkinit_core::kem_types::is_kem_rep(&pa_rep));

    let client_key = client
        .process_as_rep(
            &pa_rep,
            &pkinit_core::client::AsRepParams {
                nonce,
                enctype,
                as_req_der: as_req_full,
                pa_rep_raw: &pa_rep,
                client_name,
                server_name,
            },
            &o2k,
        )
        .unwrap();

    assert_eq!(client_key.enctype, server_key.enctype);
    assert_eq!(client_key.key_data.as_ref(), server_key.key_data.as_ref());
    assert_eq!(client_key.enctype, enctype);
    assert!(!client_key.key_data.as_ref().is_empty());
}

#[test]
fn pkinit_kem_composite_mlkem768_x25519_exchange() {
    run_composite_kem_exchange(KemAlgorithm::MlKem768X25519, 18);
}

#[test]
fn pkinit_kem_composite_mlkem768_ecdh_p256_exchange() {
    run_composite_kem_exchange(KemAlgorithm::MlKem768EcdhP256, 18);
}

#[test]
fn pkinit_kem_composite_mlkem1024_ecdh_p384_exchange() {
    run_composite_kem_exchange(KemAlgorithm::MlKem1024EcdhP384, 17);
}

#[test]
fn pkinit_kem_composite_not_opted_in_is_rejected() {
    // Composite algorithms must not be silently accepted just because ML-KEM
    // support is compiled in — default KDC config has an empty composite list.
    let (client_id, kdc_id, trust_store) = generate_test_pki(TestKeyType::EcP256);

    let client_config = PkinitClientConfig {
        kem_algorithm: Some(KemAlgorithm::MlKem768EcdhP256),
        ..Default::default()
    };
    let mut client = PkinitClientState::new(client_id, trust_store.clone(), client_config);
    client.set_kdc_identity("krbtgt/EXAMPLE.COM@EXAMPLE.COM".to_string(), None);

    let server = PkinitKdcState::new(kdc_id, trust_store, PkinitKdcConfig::default()).unwrap();

    let req_body_der = b"composite-not-opted-in-req-body";
    let nonce = next_nonce();
    let pa_req = client
        .build_as_req(nonce, 1719600000, 0, req_body_der)
        .unwrap();

    let err = server
        .verify_as_req(&pa_req, Some(req_body_der), 300, 1719600000)
        .unwrap_err();
    assert!(matches!(err, PkinitError::KemAlgorithmNotSupported(_)));
    assert_eq!(
        err.kem_error_class(),
        pkinit_core::error::KemErrorClass::EphemeralKeyParamsNotAccepted
    );
}

// --- KDC rejection -> TD-EPHEMERAL-KEY-PARAMETERS-DATA -> client retry ---
//
// Regression test for the error-65 wiring gap: the KDC must reject an
// unsupported algorithm with typed data the client can actually parse and
// act on (draft {{sec-ephemeral-key-errors}}), not a generic failure.

#[test]
fn pkinit_kem_unsupported_algorithm_td_data_enables_retry() {
    let (client_id, kdc_id, trust_store) = generate_test_pki(TestKeyType::EcP256);
    let o2k = TestO2K;

    let client_config = PkinitClientConfig {
        kem_algorithm: Some(KemAlgorithm::MlKem768),
        ..Default::default()
    };
    let mut client = PkinitClientState::new(client_id, trust_store.clone(), client_config);
    client.set_kdc_identity("krbtgt/EXAMPLE.COM@EXAMPLE.COM".to_string(), None);

    let kdc_config = PkinitKdcConfig {
        supported_kem_algorithms: vec![KemAlgorithm::MlKem1024], // rejects MlKem768
        ..Default::default()
    };
    let server = PkinitKdcState::new(kdc_id, trust_store, kdc_config).unwrap();

    let req_body_der = b"td-retry-req-body";
    let nonce = next_nonce();
    let pa_req = client
        .build_as_req(nonce, 1719600000, 0, req_body_der)
        .unwrap();

    let err = server
        .verify_as_req(&pa_req, Some(req_body_der), 300, 1719600000)
        .unwrap_err();
    assert!(matches!(err, PkinitError::KemAlgorithmNotSupported(_)));

    // Build the same typed data the KDC plugin layer would attach to the
    // KRB-ERROR, wrap it as a one-element METHOD-DATA, and feed it to the
    // client's retry handler exactly as `tryagain` would receive it.
    let td_der = server.build_td_ephemeral_key_params();
    assert!(
        !td_der.is_empty(),
        "TD-EPHEMERAL-KEY-PARAMETERS must not be empty"
    );

    // Decodes to exactly the algorithms this KDC config allows: the
    // configured KEM (MlKem1024) plus the default DH groups (Oakley2048 and
    // Oakley4096, both encoded as `dhpublicnumber` — the EC groups fall
    // below the default 2048-bit dh_min_bits floor and are absent).
    let alg_ids: Vec<synta_certificate::AlgorithmIdentifier<'_>> =
        synta::Decoder::new(&td_der, synta::Encoding::Der)
            .decode()
            .unwrap();
    for alg_id in &alg_ids {
        let oid = alg_id.algorithm.components();
        assert!(
            oid == KemAlgorithm::MlKem1024.oid()
                || oid == synta_krb5::pkix1_algorithms2008::DHPUBLICNUMBER,
            "unexpected algorithm OID in TD-EPHEMERAL-KEY-PARAMETERS: {oid:?}"
        );
    }
    assert_eq!(
        alg_ids
            .iter()
            .filter(|a| a.algorithm.components() == KemAlgorithm::MlKem1024.oid())
            .count(),
        1,
        "expected exactly one KEM AlgorithmIdentifier"
    );
    assert_eq!(
        alg_ids
            .iter()
            .filter(|a| a.algorithm.components()
                == synta_krb5::pkix1_algorithms2008::DHPUBLICNUMBER)
            .count(),
        2,
        "expected exactly two DH AlgorithmIdentifiers (Oakley2048 and Oakley4096)"
    );

    // Cached: repeated calls return byte-identical data rather than
    // rebuilding it.
    assert_eq!(
        td_der,
        server.build_td_ephemeral_key_params(),
        "TD-EPHEMERAL-KEY-PARAMETERS should be cached and stable across calls"
    );

    let padata = vec![synta_krb5::kerberos_v5::PaData {
        padata_type: synta_krb5::kerberos_v5::Int32::new_unchecked(
            synta_krb5::constants::TD_DH_PARAMETERS,
        ),
        padata_value: synta::OctetString::new(td_der),
    }];
    let padata_der = {
        use synta::ToDer;
        padata.to_der().unwrap()
    };

    let action = client.handle_tryagain(&padata_der).unwrap();
    match action {
        pkinit_core::client::RetryAction::RetryWithKemAlgorithm(alg) => {
            assert_eq!(alg, KemAlgorithm::MlKem1024);
        }
        other => panic!("expected RetryWithKemAlgorithm(MlKem1024), got {other:?}"),
    }

    // The retry itself must now succeed end-to-end.
    let nonce_2 = next_nonce();
    let pa_req_2 = client
        .build_as_req(nonce_2, 1719600000, 0, req_body_der)
        .unwrap();
    let verified_2 = server
        .verify_as_req(&pa_req_2, Some(req_body_der), 300, 1719600000)
        .unwrap();
    assert!(matches!(
        verified_2.key_exchange,
        pkinit_core::server::KeyExchangeType::Kem(KemAlgorithm::MlKem1024)
    ));

    // Complete the exchange end-to-end: the retry must not just be accepted,
    // it must produce identical keys on both sides, mirroring the KEM/composite
    // happy-path tests above.
    let as_req_full = b"td-retry-full-as-req";
    let client_name = "testuser@EXAMPLE.COM";
    let server_name = "krbtgt/EXAMPLE.COM@EXAMPLE.COM";
    let (pa_rep, server_key) = server
        .build_as_rep(
            &verified_2,
            &BuildAsRepParams {
                nonce: nonce_2,
                enctype: 18,
                as_req_der: as_req_full,
                client_name,
                server_name,
            },
            &o2k,
        )
        .unwrap();

    assert!(pkinit_core::kem_types::is_kem_rep(&pa_rep));

    let client_key = client
        .process_as_rep(
            &pa_rep,
            &pkinit_core::client::AsRepParams {
                nonce: nonce_2,
                enctype: 18,
                as_req_der: as_req_full,
                pa_rep_raw: &pa_rep,
                client_name,
                server_name,
            },
            &o2k,
        )
        .unwrap();

    assert_eq!(client_key.enctype, server_key.enctype);
    assert_eq!(client_key.key_data.as_ref(), server_key.key_data.as_ref());
}

#[test]
fn pkinit_kem_anonymous_exchange() {
    let (_, kdc_id, trust_store) = generate_test_pki(TestKeyType::EcP256);
    let o2k = TestO2K;

    let anon_identity = PkinitIdentity {
        cert_der: vec![],
        key_pkcs8_der: vec![],
        chain: vec![],
    };

    let client_config = PkinitClientConfig {
        kem_algorithm: Some(KemAlgorithm::MlKem768),
        ..Default::default()
    };
    let mut client = PkinitClientState::new(anon_identity, trust_store.clone(), client_config);
    client.set_kdc_identity("krbtgt/EXAMPLE.COM@EXAMPLE.COM".to_string(), None);

    let server = PkinitKdcState::new(kdc_id, trust_store, PkinitKdcConfig::default()).unwrap();

    let req_body_der = b"anon-kem-req-body";
    let nonce = next_nonce();
    let enctype = 18;
    let ctime = 1719600000i64;

    let pa_req = client.build_as_req(nonce, ctime, 0, req_body_der).unwrap();

    let verified = server
        .verify_as_req(&pa_req, Some(req_body_der), 300, ctime)
        .unwrap();
    assert!(verified.is_anonymous);

    let as_req_full = b"anon-kem-full-as-req";
    let client_name = "WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS";
    let server_name = "krbtgt/EXAMPLE.COM@EXAMPLE.COM";
    let (pa_rep, server_key) = server
        .build_as_rep(
            &verified,
            &BuildAsRepParams {
                nonce,
                enctype,
                as_req_der: as_req_full,
                client_name,
                server_name,
            },
            &o2k,
        )
        .unwrap();

    let client_key = client
        .process_as_rep(
            &pa_rep,
            &pkinit_core::client::AsRepParams {
                nonce,
                enctype,
                as_req_der: as_req_full,
                pa_rep_raw: &pa_rep,
                client_name,
                server_name,
            },
            &o2k,
        )
        .unwrap();

    assert_eq!(client_key.key_data.as_ref(), server_key.key_data.as_ref());
    assert_eq!(client_key.enctype, enctype);
}

// --- Anonymous with different KDC key type ---

#[test]
fn pkinit_anonymous_rsa_exchange() {
    let (_, _, trust_store) = generate_test_pki(TestKeyType::Rsa2048);
    let o2k = TestO2K;

    let anon_identity = PkinitIdentity {
        cert_der: vec![],
        key_pkcs8_der: vec![],
        chain: vec![],
    };

    let client_config = PkinitClientConfig {
        dh_group: DhGroup::EcP256,
        ..Default::default()
    };

    // KDC uses RSA-2048 cert
    let (_, kdc_id, _) = generate_test_pki(TestKeyType::Rsa2048);

    let mut client = PkinitClientState::new(anon_identity, trust_store.clone(), client_config);
    client.set_kdc_identity("krbtgt/EXAMPLE.COM@EXAMPLE.COM".to_string(), None);

    let server = PkinitKdcState::new(kdc_id, trust_store, PkinitKdcConfig::default()).unwrap();

    let req_body_der = b"anon-rsa-req-body";
    let nonce = next_nonce();
    let enctype = 18;
    let ctime = 1719600000i64;

    let pa_req = client.build_as_req(nonce, ctime, 0, req_body_der).unwrap();

    let verified = server
        .verify_as_req(&pa_req, Some(req_body_der), 300, ctime)
        .unwrap();
    assert!(verified.is_anonymous);

    let as_req_full = b"anon-rsa-full-as-req";
    let client_name = "WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS";
    let server_name = "krbtgt/EXAMPLE.COM@EXAMPLE.COM";
    let (pa_rep, server_key) = server
        .build_as_rep(
            &verified,
            &BuildAsRepParams {
                nonce,
                enctype,
                as_req_der: as_req_full,
                client_name,
                server_name,
            },
            &o2k,
        )
        .unwrap();

    let client_key = client
        .process_as_rep(
            &pa_rep,
            &pkinit_core::client::AsRepParams {
                nonce,
                enctype,
                as_req_der: as_req_full,
                pa_rep_raw: &pa_rep,
                client_name,
                server_name,
            },
            &o2k,
        )
        .unwrap();

    assert_eq!(client_key.key_data.as_ref(), server_key.key_data.as_ref());
    assert_eq!(client_key.enctype, enctype);
}
