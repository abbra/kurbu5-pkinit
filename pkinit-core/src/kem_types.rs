use synta::{Integer, OctetString};
use synta_certificate::AlgorithmIdentifier;

use crate::error::{PkinitError, asn1_err};

/// Encode a 32-bit Kerberos nonce for the PKINIT structures that carry it
/// (`PKAuthenticator.nonce`, `KDCDHKeyInfo.nonce`, `KDCKEMInfo.nonce`), all
/// `INTEGER (0..4294967295)`. Nonces are held in `i32` storage, as MIT's
/// `krb5_int32` does, so the bit pattern is reinterpreted as unsigned rather
/// than encoded as a negative INTEGER.
pub(crate) fn encode_nonce(nonce: i32) -> Integer {
    Integer::from(i64::from(nonce as u32))
}

/// Decode a PKINIT nonce (see [`encode_nonce`]), rejecting values outside
/// `0..4294967295`, back into `i32` storage.
pub(crate) fn decode_nonce(value: &Integer) -> Result<i32, PkinitError> {
    let v = value.as_i64().map_err(asn1_err("nonce"))?;
    u32::try_from(v)
        .map(|n| n as i32)
        .map_err(|_| PkinitError::Asn1(format!("nonce {v} outside 0..4294967295")))
}

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

/// PkinitKEMSuppPubInfo binds the KEM KDF to a specific exchange. It is
/// only ever the HKDF `info` input, never transmitted, and -- unlike the
/// rest of KerberosV5-PK-INIT-SPEC -- its fields are IMPLICIT tagged
/// (draft-bokovoy-kitten-pkinit-pqc-02 {{sec-asn1-types}}), so its exact
/// encoding determines the reply key.
///
/// ```asn1
/// PkinitKEMSuppPubInfo ::= SEQUENCE {
///     enctype         [0] IMPLICIT Int32,
///     as-REQ          [1] IMPLICIT OCTET STRING,
///     kemSignedData   [2] IMPLICIT OCTET STRING,
///     ...
/// }
/// ```
#[derive(Debug, Clone, PartialEq, synta::Asn1Sequence)]
pub struct PkinitKemSuppPubInfo {
    #[asn1(tag(0, implicit))]
    pub enctype: Integer,
    #[asn1(tag(1, implicit))]
    pub as_req: OctetString,
    #[asn1(tag(2, implicit))]
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

/// Context tag byte for `PA-PK-AS-REP.kemInfo [2] IMPLICIT KemRepInfo`.
///
/// Context-specific, constructed, tag number 2 (KemRepInfo is a SEQUENCE).
pub(crate) const PA_PK_AS_REP_KEM_TAG: u8 = 0xA2;

/// Check whether a DER-encoded PA-PK-AS-REP begins with the kemInfo `[2]` tag.
pub fn is_kem_rep(pa_rep_der: &[u8]) -> bool {
    pa_rep_der.first() == Some(&PA_PK_AS_REP_KEM_TAG)
}

/// Extract the OCTET STRING content from a `[2] IMPLICIT OCTET STRING` wrapper.
///
/// Parses the TLV, verifies the tag is `[2]`, and returns the value bytes
/// (which are the DER-encoded KEMRepInfo).
pub(crate) fn decode_kem_rep_content(pa_rep_der: &[u8]) -> Result<Vec<u8>, PkinitError> {
    if !is_kem_rep(pa_rep_der) {
        return Err(PkinitError::Asn1(
            "PA-PK-AS-REP: expected kemInfo [2] tag".into(),
        ));
    }
    // Skip the tag byte and parse the DER length to extract the value.
    let (len, header_size) = der_parse_length(&pa_rep_der[1..])?;
    let value_start = 1 + header_size;
    if pa_rep_der.len() < value_start + len {
        return Err(PkinitError::Asn1("kemInfo: truncated content".into()));
    }
    Ok(pa_rep_der[value_start..value_start + len].to_vec())
}

/// Encode a KEMRepInfo as a `PA-PK-AS-REP.kemInfo [2] IMPLICIT OCTET STRING`.
pub(crate) fn encode_kem_rep_wrapper(kem_rep_info: &KemRepInfo) -> Result<Vec<u8>, PkinitError> {
    let inner_der = kem_rep_info
        .to_der()
        .map_err(asn1_err("encode KEMRepInfo"))?;
    let mut out = Vec::with_capacity(1 + 4 + inner_der.len());
    out.push(PA_PK_AS_REP_KEM_TAG);
    der_encode_length(inner_der.len(), &mut out);
    out.extend_from_slice(&inner_der);
    Ok(out)
}

fn der_parse_length(data: &[u8]) -> Result<(usize, usize), PkinitError> {
    if data.is_empty() {
        return Err(PkinitError::Asn1("DER length: unexpected end".into()));
    }
    let first = data[0];
    if first < 0x80 {
        Ok((first as usize, 1))
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 4 || data.len() < 1 + n {
            return Err(PkinitError::Asn1("DER length: invalid long form".into()));
        }
        let mut len = 0usize;
        for &b in &data[1..1 + n] {
            len = len
                .checked_shl(8)
                .and_then(|l| l.checked_add(b as usize))
                .ok_or_else(|| PkinitError::Asn1("DER length: overflow".into()))?;
        }
        Ok((len, 1 + n))
    }
}

pub(crate) fn der_encode_length(len: usize, out: &mut Vec<u8>) {
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

/// OID-only form of [`encode_pkinit_hint_alg_ids`] (absent parameters),
/// for tests.
#[cfg(test)]
pub(crate) fn encode_pkinit_hint(algorithm_oids: &[&[u32]]) -> Result<Vec<u8>, PkinitError> {
    let alg_ids: Vec<AlgorithmIdentifier<'_>> = algorithm_oids
        .iter()
        .map(|oid| {
            Ok(AlgorithmIdentifier {
                algorithm: synta::ObjectIdentifier::new(oid).map_err(asn1_err("OID"))?,
                parameters: None,
            })
        })
        .collect::<Result<_, PkinitError>>()?;
    encode_pkinit_hint_alg_ids(alg_ids)
}

/// Encode a `PA-PK-AS-REQ-Hint` whose `ephemeralKeyParameters` carry full
/// `AlgorithmIdentifier`s, so DH/ECDH groups keep their domain parameters.
///
/// ```asn1
/// PA-PK-AS-REQ-Hint ::= SEQUENCE {
///     ephemeralKeyParameters [0] SEQUENCE OF AlgorithmIdentifier OPTIONAL,
///     ...
/// }
/// ```
pub(crate) fn encode_pkinit_hint_alg_ids(
    alg_ids: Vec<AlgorithmIdentifier<'_>>,
) -> Result<Vec<u8>, PkinitError> {
    use synta::Encode;

    let mut inner_encoder = synta::Encoder::new(synta::Encoding::Der);
    alg_ids
        .encode(&mut inner_encoder)
        .map_err(asn1_err("encode alg ids"))?;
    let seq_of_der = inner_encoder.finish().map_err(asn1_err("finish alg ids"))?;

    // Wrap in [0] EXPLICIT tag
    let mut tagged = Vec::with_capacity(1 + 4 + seq_of_der.len());
    tagged.push(0xA0); // context [0] constructed
    der_encode_length(seq_of_der.len(), &mut tagged);
    tagged.extend_from_slice(&seq_of_der);

    // Wrap in outer SEQUENCE
    let mut out = Vec::with_capacity(1 + 4 + tagged.len());
    out.push(0x30); // SEQUENCE
    der_encode_length(tagged.len(), &mut out);
    out.extend_from_slice(&tagged);

    Ok(out)
}

/// An offered key-establishment algorithm: its OID and, for DH/ECDH groups,
/// the DER of its domain parameters.
pub(crate) type OfferedAlgorithm = (Vec<u32>, Option<Vec<u8>>);

/// Parse `ephemeralKeyParameters` from a `PA-PK-AS-REQ-Hint`, in the KDC's
/// order of preference.
///
/// If the hint is empty or has no `ephemeralKeyParameters`, returns an empty
/// vec.
pub(crate) fn parse_pkinit_hint(hint_der: &[u8]) -> Result<Vec<OfferedAlgorithm>, PkinitError> {
    // Outer SEQUENCE
    if hint_der.is_empty() || hint_der[0] != 0x30 {
        return Err(PkinitError::Asn1(
            "PA-PK-AS-REQ-Hint: expected SEQUENCE".into(),
        ));
    }
    let (outer_len, outer_hdr) = der_parse_length(&hint_der[1..])?;
    if hint_der.len() < 1 + outer_hdr + outer_len {
        return Err(PkinitError::Asn1(
            "PA-PK-AS-REQ-Hint: truncated outer SEQUENCE".into(),
        ));
    }
    let outer_content = &hint_der[1 + outer_hdr..1 + outer_hdr + outer_len];

    if outer_content.is_empty() {
        return Ok(vec![]);
    }

    // Look for [0] EXPLICIT tag (0xA0)
    if outer_content[0] != 0xA0 {
        return Ok(vec![]);
    }
    let (tag0_len, tag0_hdr) = der_parse_length(&outer_content[1..])?;
    if outer_content.len() < 1 + tag0_hdr + tag0_len {
        return Err(PkinitError::Asn1(
            "PA-PK-AS-REQ-Hint: truncated [0] content".into(),
        ));
    }
    let tag0_content = &outer_content[1 + tag0_hdr..1 + tag0_hdr + tag0_len];

    // tag0_content is SEQUENCE OF AlgorithmIdentifier
    let alg_ids: Vec<AlgorithmIdentifier<'_>> =
        synta::Decoder::new(tag0_content, synta::Encoding::Der)
            .decode()
            .map_err(asn1_err("decode ephemeralKeyParameters"))?;

    alg_ids.iter().map(offered_algorithm).collect()
}

pub(crate) fn offered_algorithm(
    alg_id: &AlgorithmIdentifier<'_>,
) -> Result<OfferedAlgorithm, PkinitError> {
    let params = alg_id
        .parameters
        .as_ref()
        .map(synta::ToDer::to_der)
        .transpose()
        .map_err(asn1_err("encode algorithm parameters"))?;
    Ok((alg_id.algorithm.components().to_vec(), params))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::next_nonce;
    use synta::ObjectIdentifier;

    #[test]
    fn nonces_are_encoded_unsigned() {
        use synta::ToDer;
        // 0xFFFFFFFF in i32 storage is -1: on the wire it is 4294967295.
        assert_eq!(
            encode_nonce(-1).to_der().unwrap(),
            [0x02, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        for n in [0, 1, i32::MAX, i32::MIN, -1] {
            assert_eq!(decode_nonce(&encode_nonce(n)).unwrap(), n);
        }
        assert!(decode_nonce(&Integer::from(-5i64)).is_err());
        assert!(decode_nonce(&Integer::from(1i64 << 32)).is_err());
    }

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
            nonce: Some(Integer::from(next_nonce() as i64)),
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

    /// Known-answer encoding: draft-02 makes every field IMPLICIT, so the
    /// context tags are primitive (0x80..0x82) and wrap the INTEGER /
    /// OCTET STRING contents directly. Any other tagging derives a
    /// different reply key than a conformant peer.
    #[test]
    fn pkinit_kem_supp_pub_info_is_implicitly_tagged() {
        let info = PkinitKemSuppPubInfo {
            enctype: Integer::from(18),
            as_req: OctetString::new(b"AB".to_vec()),
            kem_signed_data: OctetString::new(b"CD".to_vec()),
        };
        assert_eq!(
            info.to_der().unwrap(),
            [
                0x30, 0x0b, // SEQUENCE
                0x80, 0x01, 0x12, // [0] IMPLICIT Int32 18
                0x81, 0x02, b'A', b'B', // [1] IMPLICIT OCTET STRING
                0x82, 0x02, b'C', b'D', // [2] IMPLICIT OCTET STRING
            ]
        );
    }

    #[test]
    fn is_kem_rep_detects_tag() {
        assert!(is_kem_rep(&[0xA2, 0x03, 0x01, 0x02, 0x03]));
        assert!(!is_kem_rep(&[0xA0, 0x03, 0x01, 0x02, 0x03]));
        assert!(!is_kem_rep(&[0x82, 0x03, 0x01, 0x02, 0x03]));
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

    #[test]
    fn pkinit_hint_roundtrip() {
        use crate::constants;
        let oids: Vec<&[u32]> = vec![constants::ID_ML_KEM_768, constants::ID_ML_KEM_1024];
        let hint_der = encode_pkinit_hint(&oids).unwrap();
        let parsed = parse_pkinit_hint(&hint_der).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0.as_slice(), constants::ID_ML_KEM_768);
        assert_eq!(parsed[1].0.as_slice(), constants::ID_ML_KEM_1024);
    }

    #[test]
    fn pkinit_hint_empty_oids() {
        let hint_der = encode_pkinit_hint(&[]).unwrap();
        let parsed = parse_pkinit_hint(&hint_der).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn pkinit_hint_single_oid() {
        use crate::constants;
        let oids: Vec<&[u32]> = vec![constants::ID_ML_KEM_512];
        let hint_der = encode_pkinit_hint(&oids).unwrap();
        let parsed = parse_pkinit_hint(&hint_der).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0.as_slice(), constants::ID_ML_KEM_512);
    }
}
