use synta::{GeneralizedTime, OctetStringRef, ToDer};

use crate::certauth;
use crate::config::PkinitClientConfig;
use crate::constants::{self, DhGroup};
use crate::crypto::checksum;
use crate::crypto::cms;
use crate::crypto::dh::{self, DhKeyPair};
use crate::crypto::kdf::{self, DerivedKey, OctetString2Key};
use crate::error::PkinitError;
use crate::identity::{PkinitIdentity, TrustStore};

pub enum RetryAction {
    RetryWithDhParams(DhGroup),
    RetryWithCerts,
    NoRetry,
}

pub struct PkinitClientState {
    identity: PkinitIdentity,
    trust_store: TrustStore,
    config: PkinitClientConfig,
    dh_key: Option<DhKeyPair>,
    freshness_token: Option<Vec<u8>>,
    rfc6112_kdc: bool,
    dh_nonce: Option<Vec<u8>>,
    kdc_principal: Option<String>,
    kdc_hostname: Option<String>,
}

impl PkinitClientState {
    pub fn new(
        identity: PkinitIdentity,
        trust_store: TrustStore,
        config: PkinitClientConfig,
    ) -> Self {
        Self {
            identity,
            trust_store,
            config,
            dh_key: None,
            freshness_token: None,
            rfc6112_kdc: false,
            dh_nonce: None,
            kdc_principal: None,
            kdc_hostname: None,
        }
    }

    pub fn set_freshness_token(&mut self, token: Vec<u8>) {
        self.freshness_token = Some(token);
    }

    pub fn set_rfc6112_kdc(&mut self, v: bool) {
        self.rfc6112_kdc = v;
    }

    pub fn set_kdc_identity(&mut self, principal: String, hostname: Option<String>) {
        self.kdc_principal = Some(principal);
        self.kdc_hostname = hostname;
    }

    pub fn build_as_req(
        &mut self,
        nonce: i32,
        ctime: i64,
        cusec: i32,
        req_body_der: &[u8],
    ) -> Result<Vec<u8>, PkinitError> {
        let checksums = checksum::generate_checksums(req_body_der)?;

        let gen_time = GeneralizedTime::from_unix(ctime)
            .ok_or_else(|| PkinitError::Asn1("invalid ctime".into()))?;

        let freshness_ref = self.freshness_token.as_deref();

        let pk_auth = synta_krb5::pkinit::PKAuthenticator {
            cusec: synta::Integer::from(cusec),
            ctime: gen_time,
            nonce: synta::Integer::from(nonce),
            pa_checksum: Some(OctetStringRef::new(&checksums.sha256)),
            freshness_token: freshness_ref.map(OctetStringRef::new),
        };

        if self.dh_key.is_none() {
            self.dh_key = Some(DhKeyPair::generate(self.config.dh_group)?);
        }
        let dh_key = self.dh_key.as_ref().unwrap();
        let client_spki_der = dh_key.public_key_spki_der()?;

        let client_spki_element: synta::Element<'_> =
            synta::Decoder::new(&client_spki_der, synta::Encoding::Der)
                .decode()
                .map_err(|e| PkinitError::Asn1(format!("decode SPKI element: {e}")))?;

        let dh_nonce_bytes = native_ossl::rand::Rand::bytes(32)
            .map_err(|e| PkinitError::Ossl(format!("random bytes: {e}")))?;
        self.dh_nonce = Some(dh_nonce_bytes.clone());

        let supported_kdfs = vec![
            synta_krb5::pkinit::KDFAlgorithmId {
                kdf_id: synta::ObjectIdentifier::new(constants::ID_PKINIT_KDF_AH_SHA256)
                    .map_err(|e| PkinitError::Asn1(format!("KDF OID: {e}")))?,
            },
            synta_krb5::pkinit::KDFAlgorithmId {
                kdf_id: synta::ObjectIdentifier::new(constants::ID_PKINIT_KDF_AH_SHA512)
                    .map_err(|e| PkinitError::Asn1(format!("KDF OID: {e}")))?,
            },
            synta_krb5::pkinit::KDFAlgorithmId {
                kdf_id: synta::ObjectIdentifier::new(constants::ID_PKINIT_KDF_AH_SHA1)
                    .map_err(|e| PkinitError::Asn1(format!("KDF OID: {e}")))?,
            },
        ];

        let auth_pack = synta_krb5::pkinit::AuthPack {
            pk_authenticator: pk_auth,
            client_public_value: Some(client_spki_element),
            supported_cmstypes: None,
            client_dhnonce: Some(OctetStringRef::new(&dh_nonce_bytes)),
            supported_kdfs: Some(supported_kdfs),
        };

        let auth_pack_der = auth_pack
            .to_der()
            .map_err(|e| PkinitError::Asn1(format!("encode AuthPack: {e}")))?;

        let signed_auth_pack = if self.identity.cert_der.is_empty() {
            auth_pack_der
        } else {
            let signer_key =
                synta_certificate::crypto::BackendPrivateKey::from_pkcs8_der_unchecked(
                    self.identity.key_pkcs8_der.clone(),
                );
            let extra_certs: Vec<&[u8]> =
                self.identity.chain.iter().map(|c| c.as_slice()).collect();

            cms::create_signed_data(
                &auth_pack_der,
                synta_krb5::pkinit::ID_PKINIT_AUTH_DATA,
                &signer_key,
                &self.identity.cert_der,
                &extra_certs,
                "sha256",
            )?
        };

        let pa_pk_as_req = synta_krb5::pkinit::PaPkAsReq {
            signed_auth_pack: OctetStringRef::new(&signed_auth_pack),
            trusted_certifiers: None,
            kdc_pk_id: None,
        };

        pa_pk_as_req
            .to_der()
            .map_err(|e| PkinitError::Asn1(format!("encode PA-PK-AS-REQ: {e}")))
    }

    pub fn process_as_rep(
        &mut self,
        pa_rep_der: &[u8],
        nonce: i32,
        enctype: i32,
        as_req_der: &[u8],
        pa_rep_raw: &[u8],
        o2k: &dyn OctetString2Key,
    ) -> Result<DerivedKey, PkinitError> {
        let pa_rep: synta_krb5::pkinit::PaPkAsRep<'_> =
            synta_krb5::pkinit::PaPkAsRep::from_der(pa_rep_der)
                .map_err(|e| PkinitError::Asn1(format!("decode PA-PK-AS-REP: {e}")))?;

        match pa_rep {
            synta_krb5::pkinit::PaPkAsRep::DhInfo(dh_rep_info) => {
                self.process_dh_rep(dh_rep_info, nonce, enctype, as_req_der, pa_rep_raw, o2k)
            }
            synta_krb5::pkinit::PaPkAsRep::EncKeyPack(_) => Err(PkinitError::Unsupported(
                "RSA key transport mode not supported".into(),
            )),
        }
    }

    fn process_dh_rep(
        &mut self,
        dh_rep_info: synta_krb5::pkinit::DHRepInfo<'_>,
        nonce: i32,
        enctype: i32,
        as_req_der: &[u8],
        pa_rep_raw: &[u8],
        o2k: &dyn OctetString2Key,
    ) -> Result<DerivedKey, PkinitError> {
        let verified = cms::verify_signed_data(dh_rep_info.dh_signed_data.as_bytes())?;

        if verified.content_type.as_slice() != synta_krb5::pkinit::ID_PKINIT_DHKEY_DATA {
            return Err(PkinitError::CmsContentTypeMismatch {
                expected: "id-pkinit-DHKeyData".into(),
                actual: format!("{:?}", verified.content_type),
            });
        }

        self.trust_store.validate_chain(
            &verified.signer_cert_der,
            &verified.all_certs_der,
            false,
        )?;

        certauth::verify_kdc_eku(&verified.signer_cert_der)?;

        if let Some(ref kdc_principal) = self.kdc_principal {
            certauth::verify_kdc_san(
                &verified.signer_cert_der,
                kdc_principal,
                self.kdc_hostname.as_deref(),
            )?;
        }

        let kdc_dh_key_info: synta_krb5::pkinit::KDCDHKeyInfo<'_> =
            synta_krb5::pkinit::KDCDHKeyInfo::from_der(&verified.content)
                .map_err(|e| PkinitError::Asn1(format!("decode KDCDHKeyInfo: {e}")))?;

        let reply_nonce = kdc_dh_key_info
            .nonce
            .as_i64()
            .map_err(|e| PkinitError::Asn1(format!("nonce: {e}")))?;
        if reply_nonce != nonce as i64 {
            return Err(PkinitError::NonceMismatch {
                expected: nonce,
                actual: reply_nonce as i32,
            });
        }

        let dh_key = self
            .dh_key
            .as_ref()
            .ok_or_else(|| PkinitError::DhAgreementFailed("no DH key generated".into()))?;

        let kdc_pub_bits = kdc_dh_key_info.subject_public_key.as_bytes();

        let kdc_spki_der = if dh_key.group().is_ec() {
            rebuild_ec_spki(dh_key.group(), kdc_pub_bits)?
        } else {
            rebuild_dh_spki(dh_key.group(), kdc_pub_bits)?
        };

        let shared_secret = dh_key.derive_shared_secret(&kdc_spki_der)?;

        let server_dh_nonce = dh_rep_info.server_dhnonce.map(|n| n.as_bytes().to_vec());
        let selected_kdf = dh_rep_info.kdf.as_ref().map(|k| {
            k.kdf_id.components().to_vec()
        });

        if let Some(kdf_oid) = selected_kdf {
            let mut combined_nonce = self.dh_nonce.clone().unwrap_or_default();
            if let Some(ref sn) = server_dh_nonce {
                combined_nonce.extend_from_slice(sn);
            }

            kdf::pkinit_kdf(
                &shared_secret,
                &kdf_oid,
                enctype,
                &combined_nonce,
                &[],
                as_req_der,
                pa_rep_raw,
                o2k,
            )
        } else {
            let mut combined_nonce = self.dh_nonce.clone().unwrap_or_default();
            if let Some(ref sn) = server_dh_nonce {
                combined_nonce.extend_from_slice(sn);
            }

            let mut secret_with_nonce = shared_secret;
            secret_with_nonce.extend_from_slice(&combined_nonce);

            kdf::octetstring2key(&secret_with_nonce, enctype, o2k)
        }
    }

    pub fn handle_tryagain(
        &mut self,
        error_padata_der: &[u8],
    ) -> Result<RetryAction, PkinitError> {
        let padata_list: Vec<synta_krb5::kerberos_v5::PaData> =
            synta::Decoder::new(error_padata_der, synta::Encoding::Der)
                .decode()
                .map_err(|e| PkinitError::Asn1(format!("decode error padata: {e}")))?;

        for pa in &padata_list {
            let pa_type = pa.padata_type.get();

            if pa_type == synta_krb5::constants::TD_DH_PARAMETERS {
                if let Some(group) = parse_td_dh_parameters(pa.padata_value.as_bytes()) {
                    self.dh_key = None;
                    return Ok(RetryAction::RetryWithDhParams(group));
                }
            }

            if pa_type == synta_krb5::constants::TD_TRUSTED_CERTIFIERS
                || pa_type == synta_krb5::constants::TD_PKINIT_CMS_CERTIFICATES
            {
                return Ok(RetryAction::RetryWithCerts);
            }
        }

        Ok(RetryAction::NoRetry)
    }
}

fn parse_td_dh_parameters(data: &[u8]) -> Option<DhGroup> {
    let td: synta_krb5::pkinit::TdDhParameters<'_> =
        synta_krb5::pkinit::TdDhParameters::from_der(data).ok()?;

    for elem in td.0.iter() {
        let elem_der = elem.to_der().ok()?;
        if let Ok(group) = dh::validate_dh_params(&elem_der, 0) {
            return Some(group);
        }
    }
    None
}

fn rebuild_ec_spki(group: DhGroup, pub_key_bits: &[u8]) -> Result<Vec<u8>, PkinitError> {
    let curve_oid = match group {
        DhGroup::EcP256 => synta_krb5::pkix1_algorithms2008::SECP256R1,
        DhGroup::EcP384 => synta_krb5::pkix1_algorithms2008::SECP384R1,
        DhGroup::EcP521 => synta_krb5::pkix1_algorithms2008::SECP521R1,
        _ => return Err(PkinitError::DhParamsRejected("not an EC group".into())),
    };

    let curve_oid_obj = synta::ObjectIdentifier::new(curve_oid)
        .map_err(|e| PkinitError::Asn1(format!("curve OID: {e}")))?;
    let curve_oid_der = curve_oid_obj
        .to_der()
        .map_err(|e| PkinitError::Asn1(format!("encode curve OID: {e}")))?;
    let curve_element: synta::Element<'_> =
        synta::Decoder::new(&curve_oid_der, synta::Encoding::Der)
            .decode()
            .map_err(|e| PkinitError::Asn1(format!("decode curve element: {e}")))?;

    let alg_id = synta_krb5::kerberos_v5_pkinit_agility::AlgorithmIdentifier {
        algorithm: synta::ObjectIdentifier::new(synta_krb5::pkix1_algorithms2008::ID_EC_PUBLIC_KEY)
            .map_err(|e| PkinitError::Asn1(format!("EC OID: {e}")))?,
        parameters: Some(curve_element),
    };

    let spki = synta_krb5::kerberos_v5_pkinit_agility::SubjectPublicKeyInfo {
        algorithm: alg_id,
        subject_public_key: synta::BitString::new(pub_key_bits.to_vec(), 0)
            .map_err(|e| PkinitError::Asn1(format!("BitString: {e}")))?,
    };

    spki.to_der()
        .map_err(|e| PkinitError::Asn1(format!("encode EC SPKI: {e}")))
}

fn rebuild_dh_spki(group: DhGroup, pub_key_bits: &[u8]) -> Result<Vec<u8>, PkinitError> {
    let params_der = dh::group_params_der(group)
        .ok_or_else(|| PkinitError::DhParamsRejected("unknown DH group".into()))?;

    let params_element: synta::Element<'_> =
        synta::Decoder::new(params_der, synta::Encoding::Der)
            .decode()
            .map_err(|e| PkinitError::Asn1(format!("decode DH params: {e}")))?;

    let alg_id = synta_krb5::kerberos_v5_pkinit_agility::AlgorithmIdentifier {
        algorithm: synta::ObjectIdentifier::new(
            synta_krb5::pkix1_algorithms2008::DHPUBLICNUMBER,
        )
        .map_err(|e| PkinitError::Asn1(format!("DH OID: {e}")))?,
        parameters: Some(params_element),
    };

    let spki = synta_krb5::kerberos_v5_pkinit_agility::SubjectPublicKeyInfo {
        algorithm: alg_id,
        subject_public_key: synta::BitString::new(pub_key_bits.to_vec(), 0)
            .map_err(|e| PkinitError::Asn1(format!("BitString: {e}")))?,
    };

    spki.to_der()
        .map_err(|e| PkinitError::Asn1(format!("encode DH SPKI: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_state_construction() {
        let identity = PkinitIdentity {
            cert_der: vec![],
            key_pkcs8_der: vec![],
            chain: vec![],
        };
        let store = TrustStore::new();
        let config = PkinitClientConfig::default();
        let state = PkinitClientState::new(identity, store, config);
        assert!(state.dh_key.is_none());
        assert!(state.freshness_token.is_none());
    }

    #[test]
    fn set_freshness_token() {
        let mut state = PkinitClientState::new(
            PkinitIdentity {
                cert_der: vec![],
                key_pkcs8_der: vec![],
                chain: vec![],
            },
            TrustStore::new(),
            PkinitClientConfig::default(),
        );
        state.set_freshness_token(vec![1, 2, 3]);
        assert_eq!(state.freshness_token, Some(vec![1, 2, 3]));
    }

    #[test]
    fn set_rfc6112_kdc() {
        let mut state = PkinitClientState::new(
            PkinitIdentity {
                cert_der: vec![],
                key_pkcs8_der: vec![],
                chain: vec![],
            },
            TrustStore::new(),
            PkinitClientConfig::default(),
        );
        assert!(!state.rfc6112_kdc);
        state.set_rfc6112_kdc(true);
        assert!(state.rfc6112_kdc);
    }

    #[test]
    fn handle_tryagain_empty_returns_no_retry() {
        let mut state = PkinitClientState::new(
            PkinitIdentity {
                cert_der: vec![],
                key_pkcs8_der: vec![],
                chain: vec![],
            },
            TrustStore::new(),
            PkinitClientConfig::default(),
        );
        let empty: Vec<synta_krb5::kerberos_v5::PaData> = vec![];
        let empty_der = empty
            .to_der()
            .expect("encode empty padata list");
        let result = state.handle_tryagain(&empty_der).unwrap();
        assert!(matches!(result, RetryAction::NoRetry));
    }
}
