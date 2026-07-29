use pkinit_core::client::PkinitClientState;
use pkinit_core::config::{PkinitClientConfig, PkinitKdcConfig};
use pkinit_core::constants::{self, DhGroup};
use pkinit_core::crypto::kdf::OctetString2Key;
use pkinit_core::error::PkinitError;
use pkinit_core::identity::{PkinitIdentity, TrustStore};
use pkinit_core::server::PkinitKdcState;

struct TestO2K;

impl OctetString2Key for TestO2K {
    fn random_to_key(&self, enctype: i32, random_data: &[u8]) -> Result<Vec<u8>, PkinitError> {
        let len = self.key_length(enctype)?;
        let mut key = random_data.to_vec();
        key.resize(len, 0);
        Ok(key[..len].to_vec())
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

fn generate_test_pki() -> (PkinitIdentity, PkinitIdentity, TrustStore) {
    use synta::{Integer, UtcTime};
    use synta_certificate::{
        CertificateBuilder, ExtendedKeyUsageBuilder, NameBuilder, SubjectAlternativeNameBuilder,
        Time,
    };

    let ca_pkey = {
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
    let ca_pkcs8 = ca_pkey.to_pkcs8_der().unwrap();
    let ca_spki = ca_pkey.public_key_to_der().unwrap();
    let ca_name = NameBuilder::new()
        .common_name("Test PKINIT CA")
        .build()
        .unwrap();

    let ca_backend =
        synta_certificate::crypto::BackendPrivateKey::from_pkcs8_der_unchecked(ca_pkcs8.clone());
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
            let pkey = {
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
            let pkcs8 = pkey.to_pkcs8_der().unwrap();
            let spki = pkey.public_key_to_der().unwrap();
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

#[test]
fn pkinit_dh_full_exchange_aes256() {
    let (client_id, kdc_id, trust_store) = generate_test_pki();
    let o2k = TestO2K;

    let mut client_config = PkinitClientConfig::default();
    client_config.dh_group = DhGroup::EcP256;
    let mut client = PkinitClientState::new(client_id, trust_store.clone(), client_config);
    client.set_kdc_identity("krbtgt/EXAMPLE.COM@EXAMPLE.COM".to_string(), None);

    let server = PkinitKdcState::new(kdc_id, trust_store, PkinitKdcConfig::default());

    let req_body_der = b"test-kdc-req-body";
    let nonce = 99999;
    let enctype = 18; // AES256
    let ctime = 1719600000i64;

    let pa_req = client.build_as_req(nonce, ctime, 0, req_body_der).unwrap();

    let verified = server
        .verify_as_req(&pa_req, Some(req_body_der), 300, ctime, None)
        .unwrap();
    assert!(!verified.is_anonymous);

    let as_req_full = b"test-full-as-req";
    let client_name = "testuser@EXAMPLE.COM";
    let server_name = "krbtgt/EXAMPLE.COM@EXAMPLE.COM";
    let (pa_rep, server_key) = server
        .build_as_rep(
            &verified,
            nonce,
            enctype,
            as_req_full,
            client_name,
            server_name,
            &o2k,
        )
        .unwrap();

    let client_key = client
        .process_as_rep(
            &pa_rep,
            nonce,
            enctype,
            as_req_full,
            &pa_rep,
            client_name,
            server_name,
            &o2k,
        )
        .unwrap();

    assert_eq!(client_key.enctype, server_key.enctype);
    assert_eq!(client_key.key_data, server_key.key_data);
    assert_eq!(client_key.enctype, enctype);
    assert!(!client_key.key_data.is_empty());
}

#[test]
fn pkinit_dh_full_exchange_aes128() {
    let (client_id, kdc_id, trust_store) = generate_test_pki();
    let o2k = TestO2K;

    let mut client_config = PkinitClientConfig::default();
    client_config.dh_group = DhGroup::EcP256;
    let mut client = PkinitClientState::new(client_id, trust_store.clone(), client_config);
    client.set_kdc_identity("krbtgt/EXAMPLE.COM@EXAMPLE.COM".to_string(), None);

    let server = PkinitKdcState::new(kdc_id, trust_store, PkinitKdcConfig::default());

    let req_body_der = b"test-kdc-req-body";
    let nonce = 54321;
    let enctype = 17; // AES128
    let ctime = 1719600000i64;

    let pa_req = client.build_as_req(nonce, ctime, 0, req_body_der).unwrap();

    let verified = server
        .verify_as_req(&pa_req, Some(req_body_der), 300, ctime, None)
        .unwrap();

    let as_req_full = b"test-full-as-req-128";
    let client_name = "testuser@EXAMPLE.COM";
    let server_name = "krbtgt/EXAMPLE.COM@EXAMPLE.COM";
    let (pa_rep, server_key) = server
        .build_as_rep(
            &verified,
            nonce,
            enctype,
            as_req_full,
            client_name,
            server_name,
            &o2k,
        )
        .unwrap();

    let client_key = client
        .process_as_rep(
            &pa_rep,
            nonce,
            enctype,
            as_req_full,
            &pa_rep,
            client_name,
            server_name,
            &o2k,
        )
        .unwrap();

    assert_eq!(client_key.enctype, server_key.enctype);
    assert_eq!(client_key.key_data, server_key.key_data);
    assert_eq!(client_key.enctype, enctype);
    assert_eq!(client_key.key_data.len(), 16);
}

#[test]
fn pkinit_anonymous_exchange() {
    let (_, kdc_id, trust_store) = generate_test_pki();
    let o2k = TestO2K;

    let anon_identity = PkinitIdentity {
        cert_der: vec![],
        key_pkcs8_der: vec![],
        chain: vec![],
    };

    let mut client_config = PkinitClientConfig::default();
    client_config.dh_group = DhGroup::EcP256;
    let mut client = PkinitClientState::new(anon_identity, trust_store.clone(), client_config);
    client.set_kdc_identity("krbtgt/EXAMPLE.COM@EXAMPLE.COM".to_string(), None);

    let server = PkinitKdcState::new(kdc_id, trust_store, PkinitKdcConfig::default());

    let req_body_der = b"anon-req-body";
    let nonce = 12345;
    let enctype = 18;
    let ctime = 1719600000i64;

    let pa_req = client.build_as_req(nonce, ctime, 0, req_body_der).unwrap();

    let verified = server
        .verify_as_req(&pa_req, Some(req_body_der), 300, ctime, None)
        .unwrap();
    assert!(verified.is_anonymous);

    let as_req_full = b"anon-full-as-req";
    let client_name = "WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS";
    let server_name = "krbtgt/EXAMPLE.COM@EXAMPLE.COM";
    let (pa_rep, server_key) = server
        .build_as_rep(
            &verified,
            nonce,
            enctype,
            as_req_full,
            client_name,
            server_name,
            &o2k,
        )
        .unwrap();

    let client_key = client
        .process_as_rep(
            &pa_rep,
            nonce,
            enctype,
            as_req_full,
            &pa_rep,
            client_name,
            server_name,
            &o2k,
        )
        .unwrap();

    assert_eq!(client_key.key_data, server_key.key_data);
    assert_eq!(client_key.enctype, enctype);
}
