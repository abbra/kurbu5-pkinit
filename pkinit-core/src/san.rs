use crate::error::PkinitError;
use synta::{Element, Encoding, ObjectIdentifier, ToDer};
use synta_certificate::{
    Certificate, ExtendedKeyUsage, GeneralName, GeneralNames, KeyUsage, find_extension_value,
    key_usage_bit,
};

fn parse_cert(cert_der: &[u8]) -> Result<Certificate<'_>, PkinitError> {
    Certificate::from_der(cert_der)
        .map_err(|e| PkinitError::Asn1(format!("parse certificate: {e}")))
}

fn extensions_raw<'a>(cert: &'a Certificate<'a>) -> Option<&'a [u8]> {
    cert.tbs_certificate
        .extensions
        .as_ref()
        .map(|r| r.as_bytes())
}

fn decode_san<'a>(ext_raw: &'a [u8]) -> Result<GeneralNames<'a>, PkinitError> {
    let san_bytes = match find_extension_value(ext_raw, synta_certificate::oids::SUBJECT_ALT_NAME) {
        Some(b) => b,
        None => return Ok(GeneralNames(Vec::new())),
    };
    GeneralNames::from_der(san_bytes)
        .map_err(|e| PkinitError::Asn1(format!("decode SubjectAltName: {e}")))
}

/// Extract PKINIT SAN principals from an X.509 certificate.
///
/// Returns formatted `"name@REALM"` strings for each OtherName entry
/// whose type-id matches id-pkinit-san (1.3.6.1.5.2.2).
pub fn extract_pkinit_sans(cert_der: &[u8]) -> Result<Vec<String>, PkinitError> {
    let cert = parse_cert(cert_der)?;
    let ext_raw = match extensions_raw(&cert) {
        Some(r) => r,
        None => return Ok(Vec::new()),
    };

    let sans = decode_san(ext_raw)?;

    let mut result = Vec::new();
    for gn in &sans {
        if let GeneralName::OtherName(on) = gn {
            let on_der = on
                .to_der()
                .map_err(|e| PkinitError::Asn1(format!("encode OtherName: {e}")))?;
            if let Some(principal) = synta_krb5::principal::decode_krb5_san(&on_der) {
                result.push(principal);
            }
        }
    }
    Ok(result)
}

/// Extract Microsoft UPN SANs from an X.509 certificate.
///
/// Returns UTF-8 strings for each OtherName entry whose type-id
/// matches id-ms-san-upn (1.3.6.1.4.1.311.20.2.3).
pub fn extract_upn_sans(cert_der: &[u8]) -> Result<Vec<String>, PkinitError> {
    let cert = parse_cert(cert_der)?;
    let ext_raw = match extensions_raw(&cert) {
        Some(r) => r,
        None => return Ok(Vec::new()),
    };

    let sans = decode_san(ext_raw)?;

    let ms_upn_oid = ObjectIdentifier::new(synta_certificate::oids::ID_MS_SAN_UPN)
        .map_err(|e| PkinitError::Asn1(format!("UPN OID: {e}")))?;

    let mut result = Vec::new();
    for gn in &sans {
        if let GeneralName::OtherName(on) = gn
            && on.type_id == ms_upn_oid
            && let Element::Utf8String(utf8) = &on.value
        {
            result.push(utf8.as_str().to_string());
        }
    }
    Ok(result)
}

/// Extract dNSName entries from the SubjectAlternativeName extension.
pub fn extract_dns_names(cert_der: &[u8]) -> Result<Vec<String>, PkinitError> {
    let cert = parse_cert(cert_der)?;
    let ext_raw = match extensions_raw(&cert) {
        Some(r) => r,
        None => return Ok(Vec::new()),
    };

    let sans = decode_san(ext_raw)?;

    let mut result = Vec::new();
    for gn in &sans {
        if let GeneralName::DNSName(name) = gn {
            result.push(name.as_str().to_string());
        }
    }
    Ok(result)
}

/// Extract Extended Key Usage OIDs from an X.509 certificate.
///
/// Returns each EKU OID as a `Vec<u32>` of arc components.
pub fn extract_eku_oids(cert_der: &[u8]) -> Result<Vec<Vec<u32>>, PkinitError> {
    let cert = parse_cert(cert_der)?;
    let ext_raw = match extensions_raw(&cert) {
        Some(r) => r,
        None => return Ok(Vec::new()),
    };

    let eku_bytes = match find_extension_value(ext_raw, synta_certificate::oids::EXTENDED_KEY_USAGE)
    {
        Some(b) => b,
        None => return Ok(Vec::new()),
    };

    let eku = ExtendedKeyUsage::from_der(eku_bytes)
        .map_err(|e| PkinitError::Asn1(format!("decode ExtendedKeyUsage: {e}")))?;

    Ok(eku.iter().map(|oid| oid.components().to_vec()).collect())
}

/// Extract the KeyUsage bit field from an X.509 certificate.
///
/// Returns the KeyUsage as a u16 bitmask where bit N corresponds to
/// the KEY_USAGE_* constants from synta-certificate.
pub fn extract_key_usage(cert_der: &[u8]) -> Result<u16, PkinitError> {
    let cert = parse_cert(cert_der)?;
    let ext_raw = match extensions_raw(&cert) {
        Some(r) => r,
        None => return Ok(0),
    };

    let ku_bytes = match find_extension_value(ext_raw, synta_certificate::oids::KEY_USAGE) {
        Some(b) => b,
        None => return Ok(0),
    };

    let ku = KeyUsage::from_der(ku_bytes)
        .map_err(|e| PkinitError::Asn1(format!("decode KeyUsage: {e}")))?;

    let mut bits: u16 = 0;
    for i in 0..9 {
        if key_usage_bit(&ku, i) {
            bits |= 1 << i;
        }
    }
    Ok(bits)
}

/// Encode a Microsoft UPN OtherName SEQUENCE in DER.
///
/// Builds the full `OtherName` SEQUENCE containing:
/// - `type-id`: id-ms-san-upn (1.3.6.1.4.1.311.20.2.3)
/// - `value [0] EXPLICIT`: UTF8String
pub fn encode_upn_other_name(upn: &str) -> Result<Vec<u8>, PkinitError> {
    use synta::tag::TAG_SEQUENCE;
    use synta::{Encoder, Tag, TagClass, Utf8StringRef};

    let upn_oid = ObjectIdentifier::new(synta_certificate::oids::ID_MS_SAN_UPN)
        .map_err(|e| PkinitError::Asn1(format!("UPN OID: {e}")))?;
    let upn_str = Utf8StringRef::new(upn);
    let upn_der = upn_str
        .to_der()
        .map_err(|e| PkinitError::Asn1(format!("encode UPN: {e}")))?;

    let mut enc = Encoder::new(Encoding::Der);
    enc.start_constructed_no_guard(Tag::universal_constructed(TAG_SEQUENCE))
        .map_err(|e| PkinitError::Asn1(format!("othername seq: {e}")))?;
    enc.encode(&upn_oid)
        .map_err(|e| PkinitError::Asn1(format!("encode OID: {e}")))?;

    enc.start_constructed_no_guard(Tag::new(TagClass::ContextSpecific, true, 0))
        .map_err(|e| PkinitError::Asn1(format!("value tag: {e}")))?;
    enc.write_bytes(&upn_der);
    enc.end_constructed()
        .map_err(|e| PkinitError::Asn1(format!("value end: {e}")))?;

    enc.end_constructed()
        .map_err(|e| PkinitError::Asn1(format!("othername end: {e}")))?;
    enc.finish()
        .map_err(|e| PkinitError::Asn1(format!("finish: {e}")))
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

    #[test]
    fn extract_pkinit_san_round_trip() {
        let (key, spki, name) = generate_key_and_name();
        let on_der = synta_krb5::principal::encode_krb5_san("user", "EXAMPLE.COM").unwrap();

        let san_der = SubjectAlternativeNameBuilder::new()
            .other_name(&on_der)
            .build()
            .expect("build SAN");

        let cert_der = build_cert_with_extensions(
            key.as_ref(),
            &spki,
            &name,
            vec![(synta_certificate::oids::SUBJECT_ALT_NAME, false, san_der)],
        );

        let sans = extract_pkinit_sans(&cert_der).unwrap();
        assert_eq!(sans, vec!["user@EXAMPLE.COM"]);
    }

    #[test]
    fn extract_pkinit_san_service_principal() {
        let (key, spki, name) = generate_key_and_name();
        let on_der =
            synta_krb5::principal::encode_krb5_san("krbtgt/EXAMPLE.COM", "EXAMPLE.COM").unwrap();

        let san_der = SubjectAlternativeNameBuilder::new()
            .other_name(&on_der)
            .build()
            .expect("build SAN");

        let cert_der = build_cert_with_extensions(
            key.as_ref(),
            &spki,
            &name,
            vec![(synta_certificate::oids::SUBJECT_ALT_NAME, false, san_der)],
        );

        let sans = extract_pkinit_sans(&cert_der).unwrap();
        assert_eq!(sans, vec!["krbtgt/EXAMPLE.COM@EXAMPLE.COM"]);
    }

    #[test]
    fn extract_upn_san_round_trip() {
        let (key, spki, name) = generate_key_and_name();
        let on_der = encode_upn_other_name("user@example.com").unwrap();

        let san_der = SubjectAlternativeNameBuilder::new()
            .other_name(&on_der)
            .build()
            .expect("build SAN");

        let cert_der = build_cert_with_extensions(
            key.as_ref(),
            &spki,
            &name,
            vec![(synta_certificate::oids::SUBJECT_ALT_NAME, false, san_der)],
        );

        let upns = extract_upn_sans(&cert_der).unwrap();
        assert_eq!(upns, vec!["user@example.com"]);
    }

    #[test]
    fn extract_dns_names_from_cert() {
        let (key, spki, name) = generate_key_and_name();

        let san_der = SubjectAlternativeNameBuilder::new()
            .dns_name("kdc.example.com")
            .dns_name("kdc2.example.com")
            .build()
            .expect("build SAN");

        let cert_der = build_cert_with_extensions(
            key.as_ref(),
            &spki,
            &name,
            vec![(synta_certificate::oids::SUBJECT_ALT_NAME, false, san_der)],
        );

        let dns = extract_dns_names(&cert_der).unwrap();
        assert_eq!(dns, vec!["kdc.example.com", "kdc2.example.com"]);
    }

    #[test]
    fn extract_eku_oids_from_cert() {
        let (key, spki, name) = generate_key_and_name();

        let eku_der = ExtendedKeyUsageBuilder::new()
            .add_oid(synta_certificate::oids::ID_PKINIT_KPCLIENT_AUTH)
            .build()
            .expect("build EKU");

        let cert_der = build_cert_with_extensions(
            key.as_ref(),
            &spki,
            &name,
            vec![(synta_certificate::oids::EXTENDED_KEY_USAGE, false, eku_der)],
        );

        let ekus = extract_eku_oids(&cert_der).unwrap();
        assert_eq!(ekus.len(), 1);
        assert_eq!(
            ekus[0].as_slice(),
            synta_certificate::oids::ID_PKINIT_KPCLIENT_AUTH
        );
    }

    #[test]
    fn extract_key_usage_from_cert() {
        let (key, spki, name) = generate_key_and_name();

        let ku_der = synta_certificate::encode_key_usage(
            (1 << synta_certificate::KEY_USAGE_DIGITAL_SIGNATURE)
                | (1 << synta_certificate::KEY_USAGE_KEY_AGREEMENT),
        )
        .expect("encode KU");

        let cert_der = build_cert_with_extensions(
            key.as_ref(),
            &spki,
            &name,
            vec![(synta_certificate::oids::KEY_USAGE, true, ku_der)],
        );

        let ku = extract_key_usage(&cert_der).unwrap();
        assert!(ku & (1 << synta_certificate::KEY_USAGE_DIGITAL_SIGNATURE) != 0);
        assert!(ku & (1 << synta_certificate::KEY_USAGE_KEY_AGREEMENT) != 0);
        assert!(ku & (1 << synta_certificate::KEY_USAGE_KEY_CERT_SIGN) == 0);
    }

    #[test]
    fn no_extensions_returns_empty() {
        let (key, spki, name) = generate_key_and_name();
        let cert_der = build_cert_with_extensions(key.as_ref(), &spki, &name, vec![]);

        assert!(extract_pkinit_sans(&cert_der).unwrap().is_empty());
        assert!(extract_upn_sans(&cert_der).unwrap().is_empty());
        assert!(extract_dns_names(&cert_der).unwrap().is_empty());
        assert!(extract_eku_oids(&cert_der).unwrap().is_empty());
        assert_eq!(extract_key_usage(&cert_der).unwrap(), 0);
    }

    #[test]
    fn mixed_san_types() {
        let (key, spki, name) = generate_key_and_name();
        let pkinit_on = synta_krb5::principal::encode_krb5_san("user", "EXAMPLE.COM").unwrap();
        let upn_on = encode_upn_other_name("user@example.com").unwrap();

        let san_der = SubjectAlternativeNameBuilder::new()
            .other_name(&pkinit_on)
            .other_name(&upn_on)
            .dns_name("kdc.example.com")
            .build()
            .expect("build SAN");

        let cert_der = build_cert_with_extensions(
            key.as_ref(),
            &spki,
            &name,
            vec![(synta_certificate::oids::SUBJECT_ALT_NAME, false, san_der)],
        );

        let pkinit_sans = extract_pkinit_sans(&cert_der).unwrap();
        assert_eq!(pkinit_sans, vec!["user@EXAMPLE.COM"]);

        let upns = extract_upn_sans(&cert_der).unwrap();
        assert_eq!(upns, vec!["user@example.com"]);

        let dns = extract_dns_names(&cert_der).unwrap();
        assert_eq!(dns, vec!["kdc.example.com"]);
    }
}
