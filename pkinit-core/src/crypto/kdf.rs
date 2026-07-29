use crate::constants;
use crate::error::PkinitError;

pub struct DerivedKey {
    pub enctype: i32,
    pub key_data: Vec<u8>,
}

/// Trait for Kerberos key derivation operations that require MIT krb5 internals.
/// pkinit-core defines the trait; kurbu5-pkinit provides the implementation.
pub trait OctetString2Key {
    fn random_to_key(&self, enctype: i32, random_data: &[u8]) -> Result<Vec<u8>, PkinitError>;
    fn random_length(&self, enctype: i32) -> Result<usize, PkinitError>;
    fn key_length(&self, enctype: i32) -> Result<usize, PkinitError>;
}

/// Select the best KDF algorithm from the client's supported list.
/// Server preference order: SHA-256 > SHA-1 > SHA-512.
pub fn pick_kdf_alg(client_kdfs: &[Vec<u32>]) -> Option<&'static [u32]> {
    for preferred in constants::KDF_PREFERENCE_ORDER {
        if client_kdfs.iter().any(|k| k.as_slice() == *preferred) {
            return Some(preferred);
        }
    }
    None
}

fn kdf_oid_to_digest_name(kdf_oid: &[u32]) -> Result<&'static std::ffi::CStr, PkinitError> {
    if kdf_oid == constants::ID_PKINIT_KDF_AH_SHA1 {
        Ok(c"SHA1")
    } else if kdf_oid == constants::ID_PKINIT_KDF_AH_SHA256 {
        Ok(c"SHA2-256")
    } else if kdf_oid == constants::ID_PKINIT_KDF_AH_SHA512 {
        Ok(c"SHA2-512")
    } else {
        Err(PkinitError::NoSupportedKdf)
    }
}

/// SP800-56A single-step KDF for PKINIT (RFC 8636).
///
/// Constructs OtherInfo from the KDF algorithm identifier, party U/V info
/// (DER-encoded principal names), and SuppPubInfo (enctype + AS-REQ/PA-PK-AS-REP),
/// then runs OpenSSL's SSKDF with the specified hash algorithm.
///
/// The caller must provide an `OctetString2Key` implementation for the final
/// `random_to_key` conversion.
pub fn pkinit_kdf(
    shared_secret: &[u8],
    kdf_oid: &[u32],
    enctype: i32,
    party_u_info: &[u8],
    party_v_info: &[u8],
    as_req_der: &[u8],
    pa_pk_as_rep_der: &[u8],
    o2k: &dyn OctetString2Key,
) -> Result<DerivedKey, PkinitError> {
    use synta::Encode;
    use synta_krb5::kerberos_v5_pkinit_agility::{
        AlgorithmIdentifier, OtherInfo, PkinitSuppPubInfo,
    };

    let digest_name = kdf_oid_to_digest_name(kdf_oid)?;
    let rand_len = o2k.random_length(enctype)?;

    let oid = synta::ObjectIdentifier::new(kdf_oid)
        .map_err(|e| PkinitError::Asn1(format!("KDF OID: {e}")))?;

    let supp_pub_info = PkinitSuppPubInfo {
        enctype: synta::Integer::from(enctype),
        as_req: as_req_der.to_vec().into(),
        pk_as_rep: pa_pk_as_rep_der.to_vec().into(),
    };
    let supp_pub_info_der = supp_pub_info
        .to_der()
        .map_err(|e| PkinitError::Asn1(format!("encode SuppPubInfo: {e}")))?;

    let other_info = OtherInfo {
        algorithm_id: AlgorithmIdentifier {
            algorithm: oid,
            parameters: None,
        },
        party_uinfo: party_u_info.to_vec().into(),
        party_vinfo: party_v_info.to_vec().into(),
        supp_pub_info: Some(supp_pub_info_der.into()),
        supp_priv_info: None,
    };

    let mut encoder = synta::Encoder::new(synta::Encoding::Der);
    other_info
        .encode(&mut encoder)
        .map_err(|e| PkinitError::Asn1(format!("encode OtherInfo: {e}")))?;
    let other_info_der = encoder
        .finish()
        .map_err(|e| PkinitError::Asn1(format!("finish OtherInfo: {e}")))?;

    let random_data = sskdf(digest_name, shared_secret, &other_info_der, rand_len)?;

    let key_data = o2k.random_to_key(enctype, &random_data)?;
    Ok(DerivedKey { enctype, key_data })
}

fn sskdf(
    digest_name: &std::ffi::CStr,
    secret: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, PkinitError> {
    let alg = native_ossl::kdf::KdfAlg::fetch(c"SSKDF")
        .map_err(|e| PkinitError::KdfFailed(format!("fetch SSKDF: {e}")))?;
    let mut ctx = native_ossl::kdf::KdfCtx::new(&alg)
        .map_err(|e| PkinitError::KdfFailed(format!("SSKDF ctx: {e}")))?;
    let params = native_ossl::params::ParamBuilder::new()
        .map_err(|e| PkinitError::KdfFailed(format!("param builder: {e}")))?
        .push_utf8_string(c"digest", digest_name)
        .map_err(|e| PkinitError::KdfFailed(format!("set digest: {e}")))?
        .push_octet_slice(c"key", secret)
        .map_err(|e| PkinitError::KdfFailed(format!("set key: {e}")))?
        .push_octet_slice(c"info", info)
        .map_err(|e| PkinitError::KdfFailed(format!("set info: {e}")))?
        .build()
        .map_err(|e| PkinitError::KdfFailed(format!("build params: {e}")))?;
    let mut out = vec![0u8; len];
    ctx.derive(&mut out, &params)
        .map_err(|e| PkinitError::KdfFailed(format!("SSKDF derive: {e}")))?;
    Ok(out)
}

/// Encode a `"name@REALM"` principal as KRB5PrincipalName DER for use as
/// partyUInfo/partyVInfo in the RFC 8636 KDF OtherInfo.
///
/// Per MIT krb5's `pkinit_kdf`, anonymous principals are always normalized
/// to `WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS` with name-type NT_WELLKNOWN,
/// regardless of the request realm.
pub fn encode_principal_for_kdf(name: &str) -> Result<Vec<u8>, PkinitError> {
    if is_anonymous_principal(name) {
        return synta_krb5::principal::encode_krb5_principal_name_from_parts(
            synta_krb5::constants::NT_WELLKNOWN,
            &["WELLKNOWN", "ANONYMOUS"],
            "WELLKNOWN:ANONYMOUS",
        )
        .map_err(|e| PkinitError::Asn1(format!("encode anonymous principal for KDF: {e}")));
    }

    let (pname, realm_opt) = synta_krb5::principal::parse_principal(name)
        .ok_or_else(|| PkinitError::Asn1(format!("invalid principal name: {name}")))?;
    let realm_str = realm_opt
        .as_ref()
        .map(|r| synta_krb5::principal::realm_to_string(r))
        .unwrap_or_default();
    synta_krb5::principal::encode_krb5_principal_name_from_parts(
        pname.name_type.get(),
        &pname
            .name_string
            .iter()
            .map(|s| s.as_latin1_string())
            .collect::<Vec<_>>()
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>(),
        &realm_str,
    )
    .map_err(|e| PkinitError::Asn1(format!("encode principal for KDF: {e}")))
}

fn is_anonymous_principal(name: &str) -> bool {
    let Some((pname, _)) = synta_krb5::principal::parse_principal(name) else {
        return false;
    };
    pname.name_string.len() == 2
        && pname.name_string[0].as_bytes() == b"WELLKNOWN"
        && pname.name_string[1].as_bytes() == b"ANONYMOUS"
}

/// Legacy key derivation (RFC 4556, no agility).
/// Used when no KDF OID is negotiated.
pub fn octetstring2key(
    shared_secret: &[u8],
    enctype: i32,
    o2k: &dyn OctetString2Key,
) -> Result<DerivedKey, PkinitError> {
    let rand_len = o2k.random_length(enctype)?;
    let mut random_data = vec![0u8; rand_len];
    let copy_len = rand_len.min(shared_secret.len());
    random_data[..copy_len].copy_from_slice(&shared_secret[..copy_len]);
    let key_data = o2k.random_to_key(enctype, &random_data)?;
    Ok(DerivedKey { enctype, key_data })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_kdf_prefers_sha256() {
        let client_kdfs = vec![
            constants::ID_PKINIT_KDF_AH_SHA1.to_vec(),
            constants::ID_PKINIT_KDF_AH_SHA256.to_vec(),
            constants::ID_PKINIT_KDF_AH_SHA512.to_vec(),
        ];
        let picked = pick_kdf_alg(&client_kdfs);
        assert_eq!(picked, Some(constants::ID_PKINIT_KDF_AH_SHA256));
    }

    #[test]
    fn pick_kdf_returns_none_for_empty() {
        let picked = pick_kdf_alg(&[]);
        assert!(picked.is_none());
    }

    #[test]
    fn pick_kdf_returns_none_for_unknown() {
        let client_kdfs = vec![vec![1, 2, 3, 4, 5]];
        let picked = pick_kdf_alg(&client_kdfs);
        assert!(picked.is_none());
    }

    struct MockO2K;
    impl OctetString2Key for MockO2K {
        fn random_to_key(&self, _enctype: i32, random_data: &[u8]) -> Result<Vec<u8>, PkinitError> {
            Ok(random_data.to_vec())
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

    #[test]
    fn kdf_sha256_produces_output() {
        let shared_secret = vec![0xABu8; 32];
        let party_u = b"client-principal";
        let party_v = b"kdc-principal";
        let as_req = b"mock-as-req-der";
        let pk_as_rep = b"mock-pk-as-rep-der";
        let result = pkinit_kdf(
            &shared_secret,
            constants::ID_PKINIT_KDF_AH_SHA256,
            18,
            party_u,
            party_v,
            as_req,
            pk_as_rep,
            &MockO2K,
        );
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_eq!(key.enctype, 18);
        assert_eq!(key.key_data.len(), 32);
    }

    #[test]
    fn kdf_sha1_produces_output() {
        let shared_secret = vec![0xCDu8; 32];
        let result = pkinit_kdf(
            &shared_secret,
            constants::ID_PKINIT_KDF_AH_SHA1,
            17,
            b"client",
            b"kdc",
            b"as-req",
            b"pk-as-rep",
            &MockO2K,
        );
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_eq!(key.enctype, 17);
        assert_eq!(key.key_data.len(), 16);
    }

    #[test]
    fn kdf_sha512_produces_output() {
        let shared_secret = vec![0xEFu8; 64];
        let result = pkinit_kdf(
            &shared_secret,
            constants::ID_PKINIT_KDF_AH_SHA512,
            18,
            b"client",
            b"kdc",
            b"as-req",
            b"pk-as-rep",
            &MockO2K,
        );
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_eq!(key.enctype, 18);
        assert_eq!(key.key_data.len(), 32);
    }

    #[test]
    fn kdf_different_inputs_produce_different_keys() {
        let secret1 = vec![0xAAu8; 32];
        let secret2 = vec![0xBBu8; 32];
        let key1 = pkinit_kdf(
            &secret1,
            constants::ID_PKINIT_KDF_AH_SHA256,
            18,
            b"c",
            b"s",
            b"req",
            b"rep",
            &MockO2K,
        )
        .unwrap();
        let key2 = pkinit_kdf(
            &secret2,
            constants::ID_PKINIT_KDF_AH_SHA256,
            18,
            b"c",
            b"s",
            b"req",
            b"rep",
            &MockO2K,
        )
        .unwrap();
        assert_ne!(key1.key_data, key2.key_data);
    }

    #[test]
    fn octetstring2key_basic() {
        let shared_secret = vec![0x42u8; 64];
        let key = octetstring2key(&shared_secret, 18, &MockO2K).unwrap();
        assert_eq!(key.enctype, 18);
        assert_eq!(key.key_data.len(), 32);
        assert_eq!(&key.key_data, &shared_secret[..32]);
    }

    #[test]
    fn octetstring2key_pads_short_secret() {
        let shared_secret = vec![0x42u8; 8];
        let key = octetstring2key(&shared_secret, 18, &MockO2K).unwrap();
        assert_eq!(key.key_data.len(), 32);
        assert_eq!(&key.key_data[..8], &[0x42u8; 8]);
        assert_eq!(&key.key_data[8..], &[0u8; 24]);
    }
}
