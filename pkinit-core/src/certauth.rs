use crate::constants;
use crate::error::PkinitError;
use crate::san;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertauthResult {
    Authorized,
    Rejected(String),
}

/// Verify that a client certificate's SAN matches the claimed principal.
///
/// Checks PKINIT SANs (id-pkinit-san OtherName entries) for a match
/// against `expected_principal` (a full `"name@REALM"` string). If
/// `allow_upn` is true, also checks Microsoft UPN SANs.
pub fn verify_client_san(
    cert_der: &[u8],
    expected_principal: &str,
    allow_upn: bool,
) -> Result<CertauthResult, PkinitError> {
    let pkinit_sans = san::extract_pkinit_sans(cert_der)?;
    if pkinit_sans.iter().any(|s| s == expected_principal) {
        return Ok(CertauthResult::Authorized);
    }

    if allow_upn {
        let upn_sans = san::extract_upn_sans(cert_der)?;
        if upn_sans.iter().any(|u| u.eq_ignore_ascii_case(expected_principal)) {
            return Ok(CertauthResult::Authorized);
        }
    }

    Ok(CertauthResult::Rejected(format!(
        "no SAN matching {expected_principal}"
    )))
}

/// Verify that a client certificate has the required EKU and KeyUsage.
///
/// Checks for id-pkinit-KPClientAuth in the EKU extension. If
/// `accept_secondary` is true, also accepts id-ms-kp-sc-logon.
/// Additionally verifies the digitalSignature bit in KeyUsage.
pub fn verify_client_eku(
    cert_der: &[u8],
    accept_secondary: bool,
) -> Result<CertauthResult, PkinitError> {
    let ekus = san::extract_eku_oids(cert_der)?;

    let has_pkinit_client = ekus
        .iter()
        .any(|oid| oid.as_slice() == constants::ID_PKINIT_KPCLIENT_AUTH);

    let has_ms_sc_logon = accept_secondary
        && ekus
            .iter()
            .any(|oid| oid.as_slice() == constants::ID_MS_KP_SMARTCARD_LOGON);

    if !has_pkinit_client && !has_ms_sc_logon {
        return Ok(CertauthResult::Rejected(
            "missing id-pkinit-KPClientAuth EKU".into(),
        ));
    }

    let ku = san::extract_key_usage(cert_der)?;
    if ku != 0 && (ku & (1 << synta_certificate::KEY_USAGE_DIGITAL_SIGNATURE)) == 0 {
        return Ok(CertauthResult::Rejected(
            "missing digitalSignature KeyUsage".into(),
        ));
    }

    Ok(CertauthResult::Authorized)
}

/// Verify that a KDC certificate's SAN matches the expected KDC identity.
///
/// Checks PKINIT SANs for `"krbtgt/REALM@REALM"` matching the realm
/// extracted from `kdc_principal`. If not found and `kdc_hostname` is
/// provided, checks dNSName entries.
pub fn verify_kdc_san(
    cert_der: &[u8],
    kdc_principal: &str,
    kdc_hostname: Option<&str>,
) -> Result<(), PkinitError> {
    let pkinit_sans = san::extract_pkinit_sans(cert_der)?;
    if pkinit_sans.iter().any(|s| s == kdc_principal) {
        return Ok(());
    }

    if let Some(hostname) = kdc_hostname {
        let dns_names = san::extract_dns_names(cert_der)?;
        if dns_names.iter().any(|d| d.eq_ignore_ascii_case(hostname)) {
            return Ok(());
        }
    }

    Err(PkinitError::SanMismatch(format!(
        "KDC certificate has no SAN matching {kdc_principal}"
    )))
}

/// Verify that a KDC certificate has the required EKU.
///
/// Accepts either id-pkinit-KPKdc or id-kp-serverAuth.
pub fn verify_kdc_eku(cert_der: &[u8]) -> Result<(), PkinitError> {
    let ekus = san::extract_eku_oids(cert_der)?;

    let acceptable = ekus.iter().any(|oid| {
        oid.as_slice() == constants::ID_PKINIT_KPKDC
            || oid.as_slice() == constants::ID_KP_SERVER_AUTH
    });

    if !acceptable {
        return Err(PkinitError::EkuMismatch(
            "KDC certificate missing id-pkinit-KPKdc or id-kp-serverAuth".into(),
        ));
    }

    let ku = san::extract_key_usage(cert_der)?;
    if ku != 0 && (ku & (1 << synta_certificate::KEY_USAGE_DIGITAL_SIGNATURE)) == 0 {
        return Err(PkinitError::EkuMismatch(
            "KDC certificate missing digitalSignature KeyUsage".into(),
        ));
    }

    Ok(())
}

/// Evaluate a certificate against a dbmatch rule.
pub fn db_match(cert_der: &[u8], match_rule: &str) -> Result<CertauthResult, PkinitError> {
    let matcher = crate::identity::matching::CertMatcher::parse(match_rule)?;
    if matcher.matches(cert_der)? {
        Ok(CertauthResult::Authorized)
    } else {
        Ok(CertauthResult::Rejected(
            "certificate does not match rule".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synta::{Integer, UtcTime};
    use synta_certificate::{
        CertificateBuilder, ExtendedKeyUsageBuilder, NameBuilder, PrivateKeyBuilder,
        SubjectAlternativeNameBuilder, Time,
    };

    fn generate_key_and_name() -> (Box<dyn synta_certificate::PrivateKey>, Vec<u8>, Vec<u8>) {
        let key = PrivateKeyBuilder::ec("P-256")
            .generate()
            .expect("generate key");
        let spki_der = key.public_key_spki_der().expect("public key");
        let name = NameBuilder::new()
            .common_name("Test PKINIT")
            .build()
            .expect("build name");
        (key, spki_der, name)
    }

    fn build_cert_with_extensions(
        key: &dyn synta_certificate::PrivateKey,
        spki_der: &[u8],
        name: &[u8],
        extensions: Vec<(&[u32], bool, Vec<u8>)>,
    ) -> Vec<u8> {
        let mut builder = CertificateBuilder::new()
            .subject_name(name)
            .issuer_name(name)
            .public_key_der(spki_der)
            .serial_number(Integer::from_i64(1))
            .not_valid_before(Time::UtcTime(UtcTime::new(2025, 1, 1, 0, 0, 0).unwrap()))
            .not_valid_after(Time::UtcTime(UtcTime::new(2027, 1, 1, 0, 0, 0).unwrap()));

        for (oid, critical, value) in extensions {
            builder = builder.add_extension_oid(oid, critical, &value);
        }

        builder.sign(&key.as_signer("sha256")).expect("sign cert")
    }

    fn build_client_cert(principal: &str, realm: &str) -> Vec<u8> {
        let (key, spki, name) = generate_key_and_name();
        let on_der = synta_krb5::principal::encode_krb5_san(principal, realm).unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .other_name(&on_der)
            .build()
            .unwrap();
        let eku_der = ExtendedKeyUsageBuilder::new()
            .add_oid(constants::ID_PKINIT_KPCLIENT_AUTH)
            .build()
            .unwrap();
        let ku_der = synta_certificate::encode_key_usage(
            1 << synta_certificate::KEY_USAGE_DIGITAL_SIGNATURE,
        )
        .unwrap();

        build_cert_with_extensions(
            key.as_ref(),
            &spki,
            &name,
            vec![
                (synta_certificate::oids::SUBJECT_ALT_NAME, false, san_der),
                (synta_certificate::oids::EXTENDED_KEY_USAGE, false, eku_der),
                (synta_certificate::oids::KEY_USAGE, true, ku_der),
            ],
        )
    }

    fn build_kdc_cert(realm: &str, dns_names: &[&str]) -> Vec<u8> {
        let (key, spki, name) = generate_key_and_name();
        let kdc_principal = format!("krbtgt/{realm}");
        let on_der = synta_krb5::principal::encode_krb5_san(&kdc_principal, realm).unwrap();
        let mut san_builder = SubjectAlternativeNameBuilder::new().other_name(&on_der);
        for dns in dns_names {
            san_builder = san_builder.dns_name(dns);
        }
        let san_der = san_builder.build().unwrap();
        let eku_der = ExtendedKeyUsageBuilder::new()
            .add_oid(constants::ID_PKINIT_KPKDC)
            .build()
            .unwrap();

        build_cert_with_extensions(
            key.as_ref(),
            &spki,
            &name,
            vec![
                (synta_certificate::oids::SUBJECT_ALT_NAME, false, san_der),
                (synta_certificate::oids::EXTENDED_KEY_USAGE, false, eku_der),
            ],
        )
    }

    // -- verify_client_san --

    #[test]
    fn verify_client_san_accepts_matching_pkinit_san() {
        let cert = build_client_cert("user", "EXAMPLE.COM");
        let result = verify_client_san(&cert, "user@EXAMPLE.COM", false).unwrap();
        assert_eq!(result, CertauthResult::Authorized);
    }

    #[test]
    fn verify_client_san_rejects_wrong_principal() {
        let cert = build_client_cert("user", "EXAMPLE.COM");
        let result = verify_client_san(&cert, "admin@EXAMPLE.COM", false).unwrap();
        assert!(matches!(result, CertauthResult::Rejected(_)));
    }

    #[test]
    fn verify_client_san_rejects_wrong_realm() {
        let cert = build_client_cert("user", "EXAMPLE.COM");
        let result = verify_client_san(&cert, "user@OTHER.COM", false).unwrap();
        assert!(matches!(result, CertauthResult::Rejected(_)));
    }

    #[test]
    fn verify_client_san_accepts_upn_when_allowed() {
        let (key, spki, name) = generate_key_and_name();
        let upn_on = san::encode_upn_other_name("user@EXAMPLE.COM").unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .other_name(&upn_on)
            .build()
            .unwrap();
        let cert = build_cert_with_extensions(
            key.as_ref(),
            &spki,
            &name,
            vec![(synta_certificate::oids::SUBJECT_ALT_NAME, false, san_der)],
        );

        let result = verify_client_san(&cert, "user@EXAMPLE.COM", true).unwrap();
        assert_eq!(result, CertauthResult::Authorized);
    }

    #[test]
    fn verify_client_san_rejects_upn_when_not_allowed() {
        let (key, spki, name) = generate_key_and_name();
        let upn_on = san::encode_upn_other_name("user@EXAMPLE.COM").unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .other_name(&upn_on)
            .build()
            .unwrap();
        let cert = build_cert_with_extensions(
            key.as_ref(),
            &spki,
            &name,
            vec![(synta_certificate::oids::SUBJECT_ALT_NAME, false, san_der)],
        );

        let result = verify_client_san(&cert, "user@EXAMPLE.COM", false).unwrap();
        assert!(matches!(result, CertauthResult::Rejected(_)));
    }

    // -- verify_client_eku --

    #[test]
    fn verify_client_eku_accepts_pkinit_client_auth() {
        let cert = build_client_cert("user", "EXAMPLE.COM");
        let result = verify_client_eku(&cert, false).unwrap();
        assert_eq!(result, CertauthResult::Authorized);
    }

    #[test]
    fn verify_client_eku_rejects_missing_eku() {
        let (key, spki, name) = generate_key_and_name();
        let eku_der = ExtendedKeyUsageBuilder::new()
            .add_oid(constants::ID_KP_SERVER_AUTH)
            .build()
            .unwrap();
        let ku_der = synta_certificate::encode_key_usage(
            1 << synta_certificate::KEY_USAGE_DIGITAL_SIGNATURE,
        )
        .unwrap();
        let cert = build_cert_with_extensions(
            key.as_ref(),
            &spki,
            &name,
            vec![
                (synta_certificate::oids::EXTENDED_KEY_USAGE, false, eku_der),
                (synta_certificate::oids::KEY_USAGE, true, ku_der),
            ],
        );

        let result = verify_client_eku(&cert, false).unwrap();
        assert!(matches!(result, CertauthResult::Rejected(_)));
    }

    #[test]
    fn verify_client_eku_accepts_ms_sc_logon_when_secondary() {
        let (key, spki, name) = generate_key_and_name();
        let eku_der = ExtendedKeyUsageBuilder::new()
            .add_oid(constants::ID_MS_KP_SMARTCARD_LOGON)
            .build()
            .unwrap();
        let ku_der = synta_certificate::encode_key_usage(
            1 << synta_certificate::KEY_USAGE_DIGITAL_SIGNATURE,
        )
        .unwrap();
        let cert = build_cert_with_extensions(
            key.as_ref(),
            &spki,
            &name,
            vec![
                (synta_certificate::oids::EXTENDED_KEY_USAGE, false, eku_der),
                (synta_certificate::oids::KEY_USAGE, true, ku_der),
            ],
        );

        let result = verify_client_eku(&cert, true).unwrap();
        assert_eq!(result, CertauthResult::Authorized);
    }

    #[test]
    fn verify_client_eku_rejects_missing_digital_signature() {
        let (key, spki, name) = generate_key_and_name();
        let eku_der = ExtendedKeyUsageBuilder::new()
            .add_oid(constants::ID_PKINIT_KPCLIENT_AUTH)
            .build()
            .unwrap();
        let ku_der =
            synta_certificate::encode_key_usage(1 << synta_certificate::KEY_USAGE_KEY_AGREEMENT)
                .unwrap();
        let cert = build_cert_with_extensions(
            key.as_ref(),
            &spki,
            &name,
            vec![
                (synta_certificate::oids::EXTENDED_KEY_USAGE, false, eku_der),
                (synta_certificate::oids::KEY_USAGE, true, ku_der),
            ],
        );

        let result = verify_client_eku(&cert, false).unwrap();
        assert!(matches!(result, CertauthResult::Rejected(_)));
    }

    #[test]
    fn verify_client_eku_accepts_no_key_usage_extension() {
        let (key, spki, name) = generate_key_and_name();
        let eku_der = ExtendedKeyUsageBuilder::new()
            .add_oid(constants::ID_PKINIT_KPCLIENT_AUTH)
            .build()
            .unwrap();
        let cert = build_cert_with_extensions(
            key.as_ref(),
            &spki,
            &name,
            vec![(synta_certificate::oids::EXTENDED_KEY_USAGE, false, eku_der)],
        );

        let result = verify_client_eku(&cert, false).unwrap();
        assert_eq!(result, CertauthResult::Authorized);
    }

    // -- verify_kdc_san --

    #[test]
    fn verify_kdc_san_accepts_matching_tgt_principal() {
        let cert = build_kdc_cert("EXAMPLE.COM", &[]);
        verify_kdc_san(&cert, "krbtgt/EXAMPLE.COM@EXAMPLE.COM", None).unwrap();
    }

    #[test]
    fn verify_kdc_san_rejects_wrong_realm() {
        let cert = build_kdc_cert("EXAMPLE.COM", &[]);
        let result = verify_kdc_san(&cert, "krbtgt/OTHER.COM@OTHER.COM", None);
        assert!(result.is_err());
    }

    #[test]
    fn verify_kdc_san_accepts_dns_name_fallback() {
        let cert = build_kdc_cert("EXAMPLE.COM", &["kdc.example.com"]);
        verify_kdc_san(&cert, "krbtgt/OTHER.COM@OTHER.COM", Some("kdc.example.com")).unwrap();
    }

    #[test]
    fn verify_kdc_san_dns_case_insensitive() {
        let cert = build_kdc_cert("EXAMPLE.COM", &["KDC.EXAMPLE.COM"]);
        verify_kdc_san(&cert, "krbtgt/OTHER.COM@OTHER.COM", Some("kdc.example.com")).unwrap();
    }

    // -- verify_kdc_eku --

    #[test]
    fn verify_kdc_eku_accepts_pkinit_kpkdc() {
        let cert = build_kdc_cert("EXAMPLE.COM", &[]);
        verify_kdc_eku(&cert).unwrap();
    }

    #[test]
    fn verify_kdc_eku_accepts_server_auth() {
        let (key, spki, name) = generate_key_and_name();
        let eku_der = ExtendedKeyUsageBuilder::new()
            .add_oid(constants::ID_KP_SERVER_AUTH)
            .build()
            .unwrap();
        let cert = build_cert_with_extensions(
            key.as_ref(),
            &spki,
            &name,
            vec![(synta_certificate::oids::EXTENDED_KEY_USAGE, false, eku_der)],
        );

        verify_kdc_eku(&cert).unwrap();
    }

    #[test]
    fn verify_kdc_eku_rejects_client_auth_only() {
        let (key, spki, name) = generate_key_and_name();
        let eku_der = ExtendedKeyUsageBuilder::new()
            .add_oid(constants::ID_PKINIT_KPCLIENT_AUTH)
            .build()
            .unwrap();
        let cert = build_cert_with_extensions(
            key.as_ref(),
            &spki,
            &name,
            vec![(synta_certificate::oids::EXTENDED_KEY_USAGE, false, eku_der)],
        );

        let result = verify_kdc_eku(&cert);
        assert!(result.is_err());
    }

    #[test]
    fn verify_kdc_eku_rejects_missing_digital_signature() {
        let (key, spki, name) = generate_key_and_name();
        let eku_der = ExtendedKeyUsageBuilder::new()
            .add_oid(constants::ID_PKINIT_KPKDC)
            .build()
            .unwrap();
        let ku_der =
            synta_certificate::encode_key_usage(1 << synta_certificate::KEY_USAGE_KEY_AGREEMENT)
                .unwrap();
        let cert = build_cert_with_extensions(
            key.as_ref(),
            &spki,
            &name,
            vec![
                (synta_certificate::oids::EXTENDED_KEY_USAGE, false, eku_der),
                (synta_certificate::oids::KEY_USAGE, true, ku_der),
            ],
        );

        let result = verify_kdc_eku(&cert);
        assert!(result.is_err());
    }

    #[test]
    fn verify_kdc_eku_accepts_no_key_usage_extension() {
        let (key, spki, name) = generate_key_and_name();
        let eku_der = ExtendedKeyUsageBuilder::new()
            .add_oid(constants::ID_PKINIT_KPKDC)
            .build()
            .unwrap();
        let cert = build_cert_with_extensions(
            key.as_ref(),
            &spki,
            &name,
            vec![(synta_certificate::oids::EXTENDED_KEY_USAGE, false, eku_der)],
        );

        verify_kdc_eku(&cert).unwrap();
    }

    // -- db_match --

    #[test]
    fn db_match_accepts_matching_san() {
        let cert = build_client_cert("user", "EXAMPLE.COM");
        let result = db_match(&cert, "<SAN>user@EXAMPLE.COM").unwrap();
        assert_eq!(result, CertauthResult::Authorized);
    }

    #[test]
    fn db_match_rejects_non_matching_san() {
        let cert = build_client_cert("user", "EXAMPLE.COM");
        let result = db_match(&cert, "<SAN>admin@EXAMPLE.COM").unwrap();
        assert!(matches!(result, CertauthResult::Rejected(_)));
    }
}
