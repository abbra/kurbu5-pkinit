use crate::error::PkinitError;
use synta::{
    Decoder, Encoding, ExplicitTag, ObjectIdentifier, OctetStringRef, RawDer, SetOf, Tag, ToDer,
};
use synta_certificate::{
    AlgorithmIdentifier, BackendPublicKey, Certificate, DataHasher as _, Name, PrivateKey,
    cms_2010_types::IssuerAndSerialNumber,
    cms_rfc5652_types::{Attribute, EncapsulatedContentInfo, SignedData, SignerInfo},
    digest_alg_id, pkcs7_types,
};

/// Result of verifying a CMS SignedData.
pub struct VerifiedSignedData {
    /// The encapsulated content bytes (eContent).
    pub content: Vec<u8>,
    /// The eContentType OID components.
    pub content_type: Vec<u32>,
    /// DER-encoded signer certificate.
    pub signer_cert_der: Vec<u8>,
    /// All certificates from the SignedData certificates field.
    pub all_certs_der: Vec<Vec<u8>>,
}

/// Create a CMS SignedData wrapped in ContentInfo.
///
/// Follows RFC 5652 §5:
/// 1. Hash the content with the specified digest algorithm.
/// 2. Build signedAttrs (contentType + messageDigest).
/// 3. Sign the DER-encoded signedAttrs SET.
/// 4. Assemble SignerInfo → SignedData → ContentInfo.
///
/// `content_oid` is the eContentType (e.g. id-pkinit-authData).
/// `hash_algorithm` is one of "sha1", "sha256", "sha384", "sha512".
pub fn create_signed_data(
    content: &[u8],
    content_oid: &[u32],
    signer_key: &dyn PrivateKey,
    signer_cert_der: &[u8],
    extra_certs: &[&[u8]],
    hash_algorithm: &str,
) -> Result<Vec<u8>, PkinitError> {
    let hasher = synta_certificate::default_data_hasher();

    let e_content_type = ObjectIdentifier::new(content_oid)
        .map_err(|e| PkinitError::CmsSignFailed(format!("eContentType OID: {e}")))?;

    let digest_alg = digest_alg_id(hash_algorithm)
        .ok_or_else(|| PkinitError::CmsSignFailed(format!("unsupported hash: {hash_algorithm}")))?;

    // Hash content
    let digest_bytes = hasher
        .hash_data(hash_algorithm, content)
        .map_err(|e| PkinitError::CmsSignFailed(format!("hash: {e}")))?;

    // Build signed attributes
    let (to_sign, signed_attrs_content) = build_signed_attrs(&e_content_type, &digest_bytes)
        .map_err(|e| PkinitError::CmsSignFailed(format!("signed attrs: {e}")))?;

    // Sign
    let signer = signer_key.as_signer(hash_algorithm);
    let sig_alg_bytes = signer
        .signature_algorithm_der_erased()
        .map_err(|e| PkinitError::CmsSignFailed(format!("sig alg: {e}")))?;
    let signature = signer
        .sign_tbs_erased(&to_sign)
        .map_err(|e| PkinitError::CmsSignFailed(format!("sign: {e}")))?;

    // Extract IssuerAndSerialNumber from signer cert
    let ias_der = issuer_and_serial_der(signer_cert_der)
        .map_err(|e| PkinitError::CmsSignFailed(format!("signer cert: {e}")))?;

    // Decode signature algorithm for SignerInfo
    let sig_alg = AlgorithmIdentifier::from_der(&sig_alg_bytes)
        .map_err(|e| PkinitError::CmsSignFailed(format!("decode sig alg: {e}")))?;

    // Build SignerInfo
    let signer_info = SignerInfo {
        version: synta::Integer::from_i64(1),
        sid: RawDer(&ias_der),
        digest_algorithm: digest_alg.clone(),
        signed_attrs: Some(RawDer(&signed_attrs_content)),
        signature_algorithm: sig_alg,
        signature: OctetStringRef::new(&signature),
        unsigned_attrs: None,
    };

    // Collect all cert DER bytes
    let mut all_cert_slices: Vec<&[u8]> = vec![signer_cert_der];
    all_cert_slices.extend(extra_certs);
    let certs_content: Vec<u8> = all_cert_slices.concat();

    // EncapsulatedContentInfo
    let eci = EncapsulatedContentInfo {
        e_content_type: e_content_type.clone(),
        e_content: Some(OctetStringRef::new(content)),
    };

    // SignedData
    let signed_data = SignedData {
        version: synta::Integer::from_i64(3),
        digest_algorithms: SetOf::from_vec(vec![digest_alg]),
        encap_content_info: eci,
        certificates: if certs_content.is_empty() {
            None
        } else {
            Some(RawDer(&certs_content))
        },
        crls: None,
        signer_infos: SetOf::from_vec(vec![signer_info]),
    };
    let sd_der = signed_data
        .to_der()
        .map_err(|e| PkinitError::CmsSignFailed(format!("encode SignedData: {e}")))?;

    // Wrap in ContentInfo with [0] EXPLICIT tag
    let explicit_0 = ExplicitTag::context_specific(0, RawDer(sd_der.as_slice()))
        .to_der()
        .map_err(|e| PkinitError::CmsSignFailed(format!("encode [0] EXPLICIT: {e}")))?;
    let id_signed_data = ObjectIdentifier::new(pkcs7_types::ID_SIGNED_DATA)
        .map_err(|_| PkinitError::CmsSignFailed("invalid id-signedData OID".into()))?;
    let content_info = pkcs7_types::ContentInfo {
        content_type: id_signed_data,
        content: RawDer(&explicit_0),
    };
    content_info
        .to_der()
        .map_err(|e| PkinitError::CmsSignFailed(format!("encode ContentInfo: {e}")))
}

/// Verify a CMS SignedData from a DER-encoded ContentInfo.
///
/// 1. Parses the ContentInfo and checks contentType is id-signedData.
/// 2. Extracts the SignedData, finds the first SignerInfo.
/// 3. Locates the signer certificate from the certificates field.
/// 4. Verifies the message digest in signedAttrs against the content.
/// 5. Verifies the signature over the signedAttrs using the signer's public key.
///
/// Returns the verified content and certificates.
pub fn verify_signed_data(content_info_der: &[u8]) -> Result<VerifiedSignedData, PkinitError> {
    // Parse ContentInfo
    let ci = pkcs7_types::ContentInfo::from_der(content_info_der)
        .map_err(|e| PkinitError::CmsVerifyFailed(format!("parse ContentInfo: {e}")))?;

    // Check contentType == id-signedData
    let expected_oid = ObjectIdentifier::new(pkcs7_types::ID_SIGNED_DATA)
        .map_err(|_| PkinitError::CmsVerifyFailed("invalid id-signedData OID".into()))?;
    if ci.content_type != expected_oid {
        return Err(PkinitError::CmsContentTypeMismatch {
            expected: "id-signedData".into(),
            actual: format!("{}", ci.content_type),
        });
    }

    // Unwrap [0] EXPLICIT tag to get SignedData
    let mut outer_dec = Decoder::new(ci.content.as_bytes(), Encoding::Der);
    let sd_inner = outer_dec
        .enter_constructed(Tag::context_specific_constructed(0))
        .map_err(|e| PkinitError::CmsVerifyFailed(format!("unwrap [0] EXPLICIT: {e}")))?;
    let sd_bytes = sd_inner.remaining();

    let signed_data = SignedData::from_der(sd_bytes)
        .map_err(|e| PkinitError::CmsVerifyFailed(format!("parse SignedData: {e}")))?;

    // Get the first signer info
    let signer_info = signed_data
        .signer_infos
        .elements()
        .first()
        .ok_or_else(|| PkinitError::CmsVerifyFailed("no SignerInfo present".into()))?;

    // Extract all certificates from the certificates field
    let all_certs_der = if let Some(ref certs_raw) = signed_data.certificates {
        extract_certificates(certs_raw.as_bytes())?
    } else {
        vec![]
    };

    // Find signer certificate by matching IssuerAndSerialNumber
    let signer_ias = IssuerAndSerialNumber::from_der(signer_info.sid.as_bytes())
        .map_err(|e| PkinitError::CmsVerifyFailed(format!("parse SignerIdentifier: {e}")))?;

    let signer_cert_der = find_signer_cert(&all_certs_der, &signer_ias)?;

    // Parse signer certificate to get public key
    let signer_cert = Certificate::from_der(&signer_cert_der)
        .map_err(|e| PkinitError::CmsVerifyFailed(format!("parse signer cert: {e}")))?;
    let spki_der = signer_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| PkinitError::CmsVerifyFailed(format!("encode SPKI: {e}")))?;
    let pub_key = BackendPublicKey::from_der(&spki_der)
        .map_err(|e| PkinitError::CmsVerifyFailed(format!("parse public key: {e}")))?;

    // Extract eContent
    let e_content = signed_data
        .encap_content_info
        .e_content
        .as_ref()
        .ok_or_else(|| PkinitError::CmsVerifyFailed("no eContent in SignedData".into()))?;
    let content = e_content.as_bytes().to_vec();
    let content_type = signed_data
        .encap_content_info
        .e_content_type
        .components()
        .to_vec();

    // Verify message digest in signedAttrs
    let signed_attrs_raw = signer_info
        .signed_attrs
        .as_ref()
        .ok_or_else(|| PkinitError::CmsVerifyFailed("no signedAttrs".into()))?;

    let hash_name = digest_alg_to_name(&signer_info.digest_algorithm)?;
    let hasher = synta_certificate::default_data_hasher();
    let computed_digest = hasher
        .hash_data(hash_name, &content)
        .map_err(|e| PkinitError::CmsVerifyFailed(format!("hash content: {e}")))?;

    verify_message_digest(signed_attrs_raw.as_bytes(), &computed_digest)?;

    // Reconstruct the SET OF signedAttrs (with 0x31 tag) for verification
    // The stored signedAttrs has [0] IMPLICIT tag; we need to re-tag as SET
    let to_verify = retag_as_set(signed_attrs_raw.as_bytes());

    // Verify signature
    let sig_alg_der = signer_info
        .signature_algorithm
        .to_der()
        .map_err(|e| PkinitError::CmsVerifyFailed(format!("encode sig alg: {e}")))?;
    pub_key
        .verify_signature(&to_verify, &sig_alg_der, signer_info.signature.as_bytes())
        .map_err(|e| PkinitError::CmsVerifyFailed(format!("signature invalid: {e}")))?;

    Ok(VerifiedSignedData {
        content,
        content_type,
        signer_cert_der,
        all_certs_der,
    })
}

/// Extract eContent from a CMS SignedData that has no SignerInfos (anonymous PKINIT).
///
/// Returns `Ok((content, content_type_oid))` when the input is a valid
/// ContentInfo → SignedData with zero signers.  Returns `Err` otherwise.
pub fn extract_unsigned_content(
    content_info_der: &[u8],
) -> Result<(Vec<u8>, Vec<u32>), PkinitError> {
    let ci = pkcs7_types::ContentInfo::from_der(content_info_der)
        .map_err(|e| PkinitError::CmsVerifyFailed(format!("parse ContentInfo: {e}")))?;

    let expected_oid = ObjectIdentifier::new(pkcs7_types::ID_SIGNED_DATA)
        .map_err(|_| PkinitError::CmsVerifyFailed("invalid id-signedData OID".into()))?;
    if ci.content_type != expected_oid {
        return Err(PkinitError::CmsContentTypeMismatch {
            expected: "id-signedData".into(),
            actual: format!("{}", ci.content_type),
        });
    }

    let mut outer_dec = Decoder::new(ci.content.as_bytes(), Encoding::Der);
    let sd_inner = outer_dec
        .enter_constructed(Tag::context_specific_constructed(0))
        .map_err(|e| PkinitError::CmsVerifyFailed(format!("unwrap [0] EXPLICIT: {e}")))?;
    let sd_bytes = sd_inner.remaining();

    let signed_data = SignedData::from_der(sd_bytes)
        .map_err(|e| PkinitError::CmsVerifyFailed(format!("parse SignedData: {e}")))?;

    if !signed_data.signer_infos.elements().is_empty() {
        return Err(PkinitError::CmsVerifyFailed(
            "SignedData has signers; expected unsigned anonymous content".into(),
        ));
    }

    let e_content = signed_data
        .encap_content_info
        .e_content
        .as_ref()
        .ok_or_else(|| PkinitError::CmsVerifyFailed("no eContent in SignedData".into()))?;

    let content_type = signed_data
        .encap_content_info
        .e_content_type
        .components()
        .to_vec();

    Ok((e_content.as_bytes().to_vec(), content_type))
}

/// Create a CMS SignedData wrapped in ContentInfo with no signers (anonymous PKINIT).
pub fn create_unsigned_data(content: &[u8], content_oid: &[u32]) -> Result<Vec<u8>, PkinitError> {
    let e_content_type = ObjectIdentifier::new(content_oid)
        .map_err(|e| PkinitError::CmsSignFailed(format!("eContentType OID: {e}")))?;

    let eci = EncapsulatedContentInfo {
        e_content_type,
        e_content: Some(OctetStringRef::new(content)),
    };

    let signed_data = SignedData {
        version: synta::Integer::from_i64(3),
        digest_algorithms: SetOf::from_vec(vec![]),
        encap_content_info: eci,
        certificates: None,
        crls: None,
        signer_infos: SetOf::from_vec(vec![]),
    };
    let sd_der = signed_data
        .to_der()
        .map_err(|e| PkinitError::CmsSignFailed(format!("encode SignedData: {e}")))?;

    let explicit_0 = ExplicitTag::context_specific(0, RawDer(sd_der.as_slice()))
        .to_der()
        .map_err(|e| PkinitError::CmsSignFailed(format!("encode [0] EXPLICIT: {e}")))?;
    let id_signed_data = ObjectIdentifier::new(pkcs7_types::ID_SIGNED_DATA)
        .map_err(|_| PkinitError::CmsSignFailed("invalid id-signedData OID".into()))?;
    let content_info = pkcs7_types::ContentInfo {
        content_type: id_signed_data,
        content: RawDer(&explicit_0),
    };
    content_info
        .to_der()
        .map_err(|e| PkinitError::CmsSignFailed(format!("encode ContentInfo: {e}")))
}

// ── Private helpers ─────────────────────────────────────────────────────────

fn issuer_and_serial_der(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    let cert = Certificate::from_der(cert_der).map_err(|e| format!("parse certificate: {e}"))?;
    let issuer_name = Name::from_der(cert.tbs_certificate.issuer.as_bytes())
        .map_err(|e| format!("parse issuer Name: {e}"))?;
    IssuerAndSerialNumber {
        issuer: issuer_name,
        serial_number: cert.tbs_certificate.serial_number.clone(),
    }
    .to_der()
    .map_err(|e| format!("encode IssuerAndSerialNumber: {e}"))
}

fn build_signed_attrs(
    content_oid: &ObjectIdentifier,
    digest: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let id_ct = ObjectIdentifier::new(synta_certificate::oids::PKCS9_CONTENT_TYPE)
        .map_err(|_| "invalid id-contentType OID")?;
    let id_md = ObjectIdentifier::new(synta_certificate::oids::PKCS9_MESSAGE_DIGEST)
        .map_err(|_| "invalid id-messageDigest OID")?;

    // contentType Attribute: attrValues = SET { eContentType OID }
    let ct_vals = SetOf::from_vec(vec![content_oid.clone()])
        .to_der()
        .map_err(|e| format!("encode contentType attrValues: {e}"))?;
    let ct_attr_der = Attribute {
        attr_type: id_ct,
        attr_values: RawDer(&ct_vals),
    }
    .to_der()
    .map_err(|e| format!("encode contentType Attribute: {e}"))?;

    // messageDigest Attribute: attrValues = SET { OCTET STRING digest }
    let md_vals = SetOf::from_vec(vec![OctetStringRef::new(digest)])
        .to_der()
        .map_err(|e| format!("encode messageDigest attrValues: {e}"))?;
    let md_attr_der = Attribute {
        attr_type: id_md,
        attr_values: RawDer(&md_vals),
    }
    .to_der()
    .map_err(|e| format!("encode messageDigest Attribute: {e}"))?;

    // SET OF attributes — DER-sorted by SetOf (RFC 5652 §5.4)
    let to_sign = SetOf::from_vec(vec![
        RawDer(ct_attr_der.as_slice()),
        RawDer(md_attr_der.as_slice()),
    ])
    .to_der()
    .map_err(|e| format!("encode signedAttrs SET: {e}"))?;

    // Extract SET value bytes (without 0x31 tag+len) for signed_attrs: [0] IMPLICIT
    let mut tmp = Decoder::new(&to_sign, Encoding::Der);
    let inner = tmp
        .enter_constructed(Tag::universal_constructed(17))
        .map_err(|e| format!("strip SET outer tag: {e}"))?;
    let signed_attrs_content = inner.remaining().to_vec();

    Ok((to_sign, signed_attrs_content))
}

/// Extract individual certificate DER blobs from the concatenated
/// certificates field of a SignedData (IMPLICIT SET OF Certificate).
fn extract_certificates(certs_raw: &[u8]) -> Result<Vec<Vec<u8>>, PkinitError> {
    let mut certs = Vec::new();
    let mut dec = Decoder::new(certs_raw, Encoding::Der);
    while !dec.is_empty() {
        let cert_raw: RawDer<'_> = dec
            .decode()
            .map_err(|e| PkinitError::CmsVerifyFailed(format!("parse cert in SET: {e}")))?;
        certs.push(cert_raw.as_bytes().to_vec());
    }
    Ok(certs)
}

/// Find the certificate matching IssuerAndSerialNumber.
fn find_signer_cert(
    certs: &[Vec<u8>],
    ias: &IssuerAndSerialNumber<'_>,
) -> Result<Vec<u8>, PkinitError> {
    let ias_issuer_der = ias
        .issuer
        .to_der()
        .map_err(|e| PkinitError::CmsVerifyFailed(format!("encode IAS issuer: {e}")))?;
    for cert_der in certs {
        let cert = Certificate::from_der(cert_der)
            .map_err(|e| PkinitError::CmsVerifyFailed(format!("parse cert: {e}")))?;
        if cert.tbs_certificate.serial_number == ias.serial_number
            && cert.tbs_certificate.issuer.as_bytes() == ias_issuer_der
        {
            return Ok(cert_der.clone());
        }
    }
    Err(PkinitError::CmsVerifyFailed(
        "signer certificate not found in SignedData".into(),
    ))
}

/// Map an AlgorithmIdentifier to a hash algorithm name string.
fn digest_alg_to_name(alg: &AlgorithmIdentifier<'_>) -> Result<&'static str, PkinitError> {
    let comps = alg.algorithm.components();
    if comps == synta_certificate::oids::ID_SHA1 {
        Ok("sha1")
    } else if comps == synta_certificate::oids::ID_SHA256 {
        Ok("sha256")
    } else if comps == synta_certificate::oids::ID_SHA384 {
        Ok("sha384")
    } else if comps == synta_certificate::oids::ID_SHA512 {
        Ok("sha512")
    } else {
        Err(PkinitError::CmsVerifyFailed(format!(
            "unsupported digest algorithm: {}",
            alg.algorithm
        )))
    }
}

/// Verify that signedAttrs contains a messageDigest attribute matching
/// the expected digest.
fn verify_message_digest(
    signed_attrs_content: &[u8],
    expected_digest: &[u8],
) -> Result<(), PkinitError> {
    let id_md = ObjectIdentifier::new(synta_certificate::oids::PKCS9_MESSAGE_DIGEST)
        .map_err(|_| PkinitError::CmsVerifyFailed("invalid id-messageDigest OID".into()))?;

    // Parse signed attributes — they are a sequence of Attribute values
    // (without the SET tag since it was stripped for IMPLICIT tagging)
    let mut dec = Decoder::new(signed_attrs_content, Encoding::Der);
    while !dec.is_empty() {
        let attr: Attribute<'_> = dec
            .decode()
            .map_err(|e| PkinitError::CmsVerifyFailed(format!("parse attribute: {e}")))?;
        if attr.attr_type == id_md {
            // attrValues is RawDer of a SET OF { OCTET STRING }
            // Enter the SET, then decode the OCTET STRING inside
            let mut set_dec = Decoder::new(attr.attr_values.as_bytes(), Encoding::Der);
            let mut inner = set_dec
                .enter_constructed(Tag::universal_constructed(17))
                .map_err(|e| PkinitError::CmsVerifyFailed(format!("enter attrValues SET: {e}")))?;
            let digest: OctetStringRef<'_> = inner
                .decode()
                .map_err(|e| PkinitError::CmsVerifyFailed(format!("parse digest value: {e}")))?;
            if digest.as_bytes() == expected_digest {
                return Ok(());
            } else {
                return Err(PkinitError::CmsVerifyFailed(
                    "messageDigest does not match content".into(),
                ));
            }
        }
    }
    Err(PkinitError::CmsVerifyFailed(
        "messageDigest attribute not found in signedAttrs".into(),
    ))
}

/// Re-tag the [0] IMPLICIT signed attrs content as a SET (0x31) for signing/
/// verification per RFC 5652 §5.4.
fn retag_as_set(content: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(2 + content.len());
    result.push(0x31); // SET tag
    encode_der_length(&mut result, content.len());
    result.extend_from_slice(content);
    result
}

fn encode_der_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len < 0x10000 {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else if len < 0x100_0000 {
        buf.push(0x83);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else {
        buf.push(0x84);
        buf.push((len >> 24) as u8);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synta_certificate::PrivateKeyBuilder;

    fn generate_test_keypair_and_cert() -> (Box<dyn PrivateKey>, Vec<u8>) {
        use synta::{Integer, UtcTime};
        use synta_certificate::{CertificateBuilder, NameBuilder, Time};

        let key = PrivateKeyBuilder::ec("P-256")
            .generate()
            .expect("generate key");

        let spki_der = key.public_key_spki_der().expect("public key");
        let name = NameBuilder::new()
            .common_name("Test PKINIT Signer")
            .build()
            .expect("build name");

        let cert_der = CertificateBuilder::new()
            .subject_name(&name)
            .issuer_name(&name)
            .public_key_der(&spki_der)
            .serial_number(Integer::from_i64(1))
            .not_valid_before(Time::UtcTime(UtcTime::new(2025, 1, 1, 0, 0, 0).unwrap()))
            .not_valid_after(Time::UtcTime(UtcTime::new(2027, 1, 1, 0, 0, 0).unwrap()))
            .sign(&key.as_signer("sha256"))
            .expect("sign cert");

        (key, cert_der)
    }

    #[test]
    fn round_trip_signed_data() {
        let (key, cert_der) = generate_test_keypair_and_cert();
        let content = b"test PKINIT content";
        let content_oid: &[u32] = &[1, 3, 6, 1, 5, 2, 3, 1]; // id-pkinit-authData

        let ci_der =
            create_signed_data(content, content_oid, key.as_ref(), &cert_der, &[], "sha256")
                .expect("create signed data");

        let verified = verify_signed_data(&ci_der).expect("verify signed data");
        assert_eq!(verified.content, content);
        assert_eq!(verified.content_type, content_oid);
        assert_eq!(verified.signer_cert_der, cert_der);
        assert_eq!(verified.all_certs_der.len(), 1);
    }

    #[test]
    fn round_trip_with_extra_certs() {
        let (key, cert_der) = generate_test_keypair_and_cert();
        let (_, extra_cert) = generate_test_keypair_and_cert();
        let content = b"test with extra certs";
        let content_oid: &[u32] = &[1, 3, 6, 1, 5, 2, 3, 1];

        let ci_der = create_signed_data(
            content,
            content_oid,
            key.as_ref(),
            &cert_der,
            &[&extra_cert],
            "sha256",
        )
        .expect("create signed data");

        let verified = verify_signed_data(&ci_der).expect("verify signed data");
        assert_eq!(verified.content, content);
        assert_eq!(verified.all_certs_der.len(), 2);
    }

    #[test]
    fn verify_rejects_tampered_content() {
        let (key, cert_der) = generate_test_keypair_and_cert();
        let content = b"original content";
        let content_oid: &[u32] = &[1, 3, 6, 1, 5, 2, 3, 1];

        let ci_der =
            create_signed_data(content, content_oid, key.as_ref(), &cert_der, &[], "sha256")
                .expect("create signed data");

        // Tamper with the ContentInfo (flip a byte in the content area)
        let mut tampered = ci_der.clone();
        if tampered.len() > 50 {
            let idx = tampered.len() - 50;
            tampered[idx] ^= 0xFF;
        }
        assert!(verify_signed_data(&tampered).is_err());
    }

    #[test]
    fn create_with_sha384() {
        let (key, cert_der) = generate_test_keypair_and_cert();
        let content = b"sha384 content";
        let content_oid: &[u32] = &[1, 3, 6, 1, 5, 2, 3, 1];

        let ci_der =
            create_signed_data(content, content_oid, key.as_ref(), &cert_der, &[], "sha384")
                .expect("create signed data");

        let verified = verify_signed_data(&ci_der).expect("verify sha384");
        assert_eq!(verified.content, content);
    }

    #[test]
    fn create_with_sha512() {
        let (key, cert_der) = generate_test_keypair_and_cert();
        let content = b"sha512 content";
        let content_oid: &[u32] = &[1, 3, 6, 1, 5, 2, 3, 1];

        let ci_der =
            create_signed_data(content, content_oid, key.as_ref(), &cert_der, &[], "sha512")
                .expect("create signed data");

        let verified = verify_signed_data(&ci_der).expect("verify sha512");
        assert_eq!(verified.content, content);
    }

    #[test]
    fn create_rejects_unsupported_hash() {
        let (key, cert_der) = generate_test_keypair_and_cert();
        let result = create_signed_data(b"test", &[1, 2, 3], key.as_ref(), &cert_der, &[], "md5");
        assert!(result.is_err());
    }

    #[test]
    fn unsigned_round_trip() {
        let content = b"anonymous auth pack";
        let content_oid: &[u32] = &[1, 3, 6, 1, 5, 2, 3, 1];

        let ci_der = create_unsigned_data(content, content_oid).expect("create unsigned data");

        let (extracted, ct) = extract_unsigned_content(&ci_der).expect("extract unsigned content");
        assert_eq!(extracted, content);
        assert_eq!(ct.as_slice(), content_oid);
    }
}
