//! Test-only helpers shared between this crate's unit tests and its
//! integration tests under `tests/`.

use std::sync::atomic::{AtomicI32, Ordering};

use native_ossl::pkey::{KeygenCtx, Pkey, Private};
use synta::{Integer, UtcTime};
use synta_certificate::{
    CertificateBuilder, ExtendedKeyUsageBuilder, NameBuilder, SubjectAlternativeNameBuilder, Time,
};

/// A fresh nonce for each exchange, instead of hardcoding the same literal
/// at every call site.
pub fn next_nonce() -> i32 {
    static NEXT: AtomicI32 = AtomicI32::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// A minimal KDC certificate chain for tests: a self-signed CA and a KDC leaf
/// signed by it, carrying the id-pkinit-KPKdc EKU and a `krbtgt/REALM@REALM`
/// PKINIT SAN so `verify_kdc_eku`/`verify_kdc_san` accept it.
pub struct TestKdcChain {
    pub ca_der: Vec<u8>,
    pub kdc_leaf_der: Vec<u8>,
}

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

#[allow(clippy::too_many_arguments)]
fn sign_cert(
    issuer_key: &Pkey<Private>,
    subject_name: &[u8],
    issuer_name: &[u8],
    subject_spki_der: &[u8],
    issuer_spki_der: &[u8],
    serial: i64,
    ca: bool,
    extra_exts: &[(&[u32], bool, &[u8])],
) -> Vec<u8> {
    let pkcs8 = issuer_key.to_pkcs8_der().expect("PKCS#8 DER");
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
        builder =
            builder.add_extension_oid(synta_certificate::oids::BASIC_CONSTRAINTS, true, &bc_der);
    }
    for (oid, critical, value) in extra_exts {
        builder = builder.add_extension_oid(oid, *critical, value);
    }

    builder.sign(&signer).expect("sign cert")
}

/// Build a CA + KDC-leaf chain for `realm` (e.g. `"EXAMPLE.COM"`). The leaf's
/// PKINIT SAN is `krbtgt/REALM@REALM`.
pub fn build_kdc_chain(realm: &str) -> TestKdcChain {
    let ca_key = generate_ec_key();
    let ca_spki = ca_key.public_key_to_der().unwrap();
    let ca_name = NameBuilder::new()
        .common_name("Test KDC CA")
        .build()
        .unwrap();
    let ca_der = sign_cert(
        &ca_key,
        &ca_name,
        &ca_name,
        &ca_spki,
        &ca_spki,
        1,
        true,
        &[],
    );

    let kdc_key = generate_ec_key();
    let kdc_spki = kdc_key.public_key_to_der().unwrap();
    let kdc_name = NameBuilder::new().common_name("Test KDC").build().unwrap();

    let kdc_principal = format!("krbtgt/{realm}");
    let on_der = synta_krb5::principal::encode_krb5_san(&kdc_principal, realm).unwrap();
    let san_der = SubjectAlternativeNameBuilder::new()
        .other_name(&on_der)
        .build()
        .unwrap();
    let eku_der = ExtendedKeyUsageBuilder::new()
        .add_oid(crate::constants::ID_PKINIT_KPKDC)
        .build()
        .unwrap();

    let kdc_leaf_der = sign_cert(
        &ca_key,
        &kdc_name,
        &ca_name,
        &kdc_spki,
        &ca_spki,
        2,
        false,
        &[
            (synta_certificate::oids::SUBJECT_ALT_NAME, false, &san_der),
            (synta_certificate::oids::EXTENDED_KEY_USAGE, false, &eku_der),
        ],
    );

    TestKdcChain {
        ca_der,
        kdc_leaf_der,
    }
}
