use synta::{Integer, OctetString};
use synta_certificate::AlgorithmIdentifier;

/// KEMRepInfo carries the KDC's KEM response.
///
/// ```asn1
/// KEMRepInfo ::= SEQUENCE {
///     kemSignedData   [0] IMPLICIT OCTET STRING,
///     ...
/// }
/// ```
#[derive(Debug, Clone, PartialEq, synta::Asn1Sequence)]
pub struct KemRepInfo {
    #[asn1(tag(0, implicit))]
    pub kem_signed_data: OctetString,
}

impl KemRepInfo {
    pub fn from_der(data: &[u8]) -> synta::Result<Self> {
        synta::Decoder::new(data, synta::Encoding::Der).decode::<Self>()
    }

    pub fn to_der(&self) -> synta::Result<Vec<u8>> {
        use synta::Encode;
        let mut encoder = synta::Encoder::new(synta::Encoding::Der);
        self.encode(&mut encoder)?;
        encoder.finish()
    }
}

/// KDCKEMInfo carries the KDC's KEM algorithm selection and ciphertext.
///
/// ```asn1
/// KDCKEMInfo ::= SEQUENCE {
///     kemAlgorithm    [0] AlgorithmIdentifier,
///     kemct           [1] OCTET STRING,
///     kdfAlgorithm    [2] AlgorithmIdentifier,
///     nonce           [3] INTEGER (0..4294967295) OPTIONAL,
///     serverNonce     [4] OCTET STRING OPTIONAL,
///     ...
/// }
/// ```
#[derive(Debug, Clone, PartialEq, synta::Asn1Sequence)]
pub struct KdcKemInfo<'a> {
    #[asn1(tag(0, explicit))]
    pub kem_algorithm: AlgorithmIdentifier<'a>,
    #[asn1(tag(1, explicit))]
    pub kemct: OctetString,
    #[asn1(tag(2, explicit))]
    pub kdf_algorithm: AlgorithmIdentifier<'a>,
    #[asn1(tag(3, explicit))]
    #[asn1(optional)]
    pub nonce: Option<Integer>,
    #[asn1(tag(4, explicit))]
    #[asn1(optional)]
    pub server_nonce: Option<OctetString>,
}

impl<'a> KdcKemInfo<'a> {
    pub fn from_der(data: &'a [u8]) -> synta::Result<Self> {
        synta::Decoder::new(data, synta::Encoding::Der).decode::<Self>()
    }

    pub fn to_der(&self) -> synta::Result<Vec<u8>> {
        use synta::Encode;
        let mut encoder = synta::Encoder::new(synta::Encoding::Der);
        self.encode(&mut encoder)?;
        encoder.finish()
    }
}

/// PkinitKEMSuppPubInfo binds the KEM KDF to a specific exchange.
///
/// ```asn1
/// PkinitKEMSuppPubInfo ::= SEQUENCE {
///     enctype         [0] Int32,
///     as-REQ          [1] OCTET STRING,
///     kemSignedData   [2] OCTET STRING,
///     ...
/// }
/// ```
#[derive(Debug, Clone, PartialEq, synta::Asn1Sequence)]
pub struct PkinitKemSuppPubInfo {
    #[asn1(tag(0, explicit))]
    pub enctype: Integer,
    #[asn1(tag(1, explicit))]
    pub as_req: OctetString,
    #[asn1(tag(2, explicit))]
    pub kem_signed_data: OctetString,
}

impl PkinitKemSuppPubInfo {
    pub fn from_der(data: &[u8]) -> synta::Result<Self> {
        synta::Decoder::new(data, synta::Encoding::Der).decode::<Self>()
    }

    pub fn to_der(&self) -> synta::Result<Vec<u8>> {
        use synta::Encode;
        let mut encoder = synta::Encoder::new(synta::Encoding::Der);
        self.encode(&mut encoder)?;
        encoder.finish()
    }
}

/// Context tag byte for `PA-PK-AS-REP.kemInfo [2] IMPLICIT OCTET STRING`.
///
/// Context-specific, primitive, tag number 2.
pub const PA_PK_AS_REP_KEM_TAG: u8 = 0x82;

/// Check whether a DER-encoded PA-PK-AS-REP begins with the kemInfo [2] tag.
pub fn is_kem_rep(pa_rep_der: &[u8]) -> bool {
    pa_rep_der.first() == Some(&PA_PK_AS_REP_KEM_TAG)
}

/// Extract the OCTET STRING content from a `[2] IMPLICIT OCTET STRING` wrapper.
///
/// Parses the TLV, verifies the tag is `[2]`, and returns the value bytes
/// (which are the DER-encoded KEMRepInfo).
pub fn decode_kem_rep_content(pa_rep_der: &[u8]) -> Result<Vec<u8>, crate::error::PkinitError> {
    if !is_kem_rep(pa_rep_der) {
        return Err(crate::error::PkinitError::Asn1(
            "PA-PK-AS-REP: expected kemInfo [2] tag".into(),
        ));
    }
    // Skip the tag byte and parse the DER length to extract the value.
    let (len, header_size) = der_parse_length(&pa_rep_der[1..])?;
    let value_start = 1 + header_size;
    if pa_rep_der.len() < value_start + len {
        return Err(crate::error::PkinitError::Asn1(
            "kemInfo: truncated content".into(),
        ));
    }
    Ok(pa_rep_der[value_start..value_start + len].to_vec())
}

/// Encode a KEMRepInfo as a `PA-PK-AS-REP.kemInfo [2] IMPLICIT OCTET STRING`.
pub fn encode_kem_rep_wrapper(
    kem_rep_info: &KemRepInfo,
) -> Result<Vec<u8>, crate::error::PkinitError> {
    let inner_der = kem_rep_info
        .to_der()
        .map_err(|e| crate::error::PkinitError::Asn1(format!("encode KEMRepInfo: {e}")))?;
    let mut out = Vec::with_capacity(1 + 4 + inner_der.len());
    out.push(PA_PK_AS_REP_KEM_TAG);
    der_encode_length(inner_der.len(), &mut out);
    out.extend_from_slice(&inner_der);
    Ok(out)
}

fn der_parse_length(data: &[u8]) -> Result<(usize, usize), crate::error::PkinitError> {
    if data.is_empty() {
        return Err(crate::error::PkinitError::Asn1(
            "DER length: unexpected end".into(),
        ));
    }
    let first = data[0];
    if first < 0x80 {
        Ok((first as usize, 1))
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 4 || data.len() < 1 + n {
            return Err(crate::error::PkinitError::Asn1(
                "DER length: invalid long form".into(),
            ));
        }
        let mut len = 0usize;
        for &b in &data[1..1 + n] {
            len = len
                .checked_shl(8)
                .and_then(|l| l.checked_add(b as usize))
                .ok_or_else(|| crate::error::PkinitError::Asn1("DER length: overflow".into()))?;
        }
        Ok((len, 1 + n))
    }
}

fn der_encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else if len <= 0xFF_FFFF {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x84);
        out.push((len >> 24) as u8);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synta::ObjectIdentifier;

    #[test]
    fn kem_rep_info_roundtrip() {
        let info = KemRepInfo {
            kem_signed_data: OctetString::new(vec![0x01, 0x02, 0x03]),
        };
        let der = info.to_der().unwrap();
        let decoded = KemRepInfo::from_der(&der).unwrap();
        assert_eq!(info, decoded);
    }

    #[test]
    fn kdc_kem_info_roundtrip() {
        let oid = ObjectIdentifier::new(&[2, 16, 840, 1, 101, 3, 4, 4, 2]).unwrap();
        let kdf_oid = ObjectIdentifier::new(&[1, 2, 840, 113549, 1, 9, 16, 3, 30]).unwrap();
        let info = KdcKemInfo {
            kem_algorithm: AlgorithmIdentifier {
                algorithm: oid,
                parameters: None,
            },
            kemct: OctetString::new(vec![0xAA; 32]),
            kdf_algorithm: AlgorithmIdentifier {
                algorithm: kdf_oid,
                parameters: None,
            },
            nonce: Some(Integer::from(99999i64)),
            server_nonce: None,
        };
        let der = info.to_der().unwrap();
        let decoded = KdcKemInfo::from_der(&der).unwrap();
        assert_eq!(info, decoded);
    }

    #[test]
    fn kdc_kem_info_without_optional_fields() {
        let oid = ObjectIdentifier::new(&[2, 16, 840, 1, 101, 3, 4, 4, 2]).unwrap();
        let kdf_oid = ObjectIdentifier::new(&[1, 2, 840, 113549, 1, 9, 16, 3, 30]).unwrap();
        let info = KdcKemInfo {
            kem_algorithm: AlgorithmIdentifier {
                algorithm: oid,
                parameters: None,
            },
            kemct: OctetString::new(vec![0xBB; 1088]),
            kdf_algorithm: AlgorithmIdentifier {
                algorithm: kdf_oid,
                parameters: None,
            },
            nonce: None,
            server_nonce: None,
        };
        let der = info.to_der().unwrap();
        let decoded = KdcKemInfo::from_der(&der).unwrap();
        assert_eq!(info, decoded);
    }

    #[test]
    fn pkinit_kem_supp_pub_info_roundtrip() {
        let info = PkinitKemSuppPubInfo {
            enctype: Integer::from(18i64),
            as_req: OctetString::new(b"mock-as-req".to_vec()),
            kem_signed_data: OctetString::new(b"mock-kem-signed-data".to_vec()),
        };
        let der = info.to_der().unwrap();
        let decoded = PkinitKemSuppPubInfo::from_der(&der).unwrap();
        assert_eq!(info, decoded);
    }

    #[test]
    fn is_kem_rep_detects_tag() {
        assert!(is_kem_rep(&[0x82, 0x03, 0x01, 0x02, 0x03]));
        assert!(!is_kem_rep(&[0xA0, 0x03, 0x01, 0x02, 0x03]));
        assert!(!is_kem_rep(&[0x81, 0x03, 0x01, 0x02, 0x03]));
        assert!(!is_kem_rep(&[]));
    }

    #[test]
    fn kem_rep_wrapper_roundtrip() {
        let info = KemRepInfo {
            kem_signed_data: OctetString::new(vec![0xDE, 0xAD]),
        };
        let wrapped = encode_kem_rep_wrapper(&info).unwrap();
        assert!(is_kem_rep(&wrapped));
        let content = decode_kem_rep_content(&wrapped).unwrap();
        let decoded = KemRepInfo::from_der(&content).unwrap();
        assert_eq!(info, decoded);
    }
}
