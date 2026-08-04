use synta::{GeneralizedTime, OctetStringRef, ToDer};

use crate::certauth;
use crate::config::PkinitClientConfig;
use crate::constants::{self, DhGroup, KemAlgorithm, KeyExchangeType};
use crate::crypto::checksum;
use crate::crypto::cms;
use crate::crypto::dh::{self, DhKeyPair};
use crate::crypto::kdf::{self, DerivedKey, OctetString2Key, encode_principal_for_kdf};
use crate::crypto::kem::KemKeyPair;
use crate::error::{PkinitError, asn1_err};
use crate::identity::{PkinitIdentity, TrustStore};

pub struct AsRepParams<'a> {
    pub nonce: i32,
    pub enctype: i32,
    pub as_req_der: &'a [u8],
    pub pa_rep_raw: &'a [u8],
    pub client_name: &'a str,
    pub server_name: &'a str,
}

#[derive(Debug)]
pub enum RetryAction {
    RetryWithDhParams(DhGroup),
    RetryWithKemAlgorithm(KemAlgorithm),
    RetryWithCerts,
    NoRetry,
}

pub struct PkinitClientState {
    identity: PkinitIdentity,
    trust_store: TrustStore,
    config: PkinitClientConfig,
    dh_key: Option<DhKeyPair>,
    kem_key: Option<KemKeyPair>,
    freshness_token: Option<Vec<u8>>,
    dh_nonce: Option<Vec<u8>>,
    kdc_principal: Option<String>,
    kdc_hostname: Option<String>,
    /// The key-establishment path and algorithm chosen for the most recent
    /// `build_as_req` call. Set once per exchange and left in place through
    /// the matching `process_as_rep` call, so callers (the krb5 plugin's
    /// tracing) can report it at either point without re-deriving it from
    /// `dh_key`/`kem_key`, whose presence changes independently (e.g.
    /// `process_kem_rep` consumes `kem_key` via `take()`).
    key_exchange: Option<KeyExchangeType>,
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
            kem_key: None,
            freshness_token: None,
            dh_nonce: None,
            kdc_principal: None,
            kdc_hostname: None,
            key_exchange: None,
        }
    }

    pub fn has_dh_key(&self) -> bool {
        self.dh_key.is_some()
    }

    pub fn has_kem_key(&self) -> bool {
        self.kem_key.is_some()
    }

    /// The key-establishment path and algorithm chosen by the most recent
    /// `build_as_req` call, or `None` before the first request is built.
    pub fn key_exchange(&self) -> Option<KeyExchangeType> {
        self.key_exchange
    }

    pub fn has_pq_certificate(&self) -> bool {
        !self.identity.cert_der.is_empty() && is_pq_signing_certificate(&self.identity.cert_der)
    }

    pub fn set_freshness_token(&mut self, token: Vec<u8>) {
        self.freshness_token = Some(token);
    }

    pub fn set_kdc_identity(&mut self, principal: String, hostname: Option<String>) {
        self.kdc_principal = Some(principal);
        self.kdc_hostname = hostname;
    }

    pub fn process_pkinit_hint(&mut self, hint_der: &[u8]) -> Result<(), PkinitError> {
        let oids = crate::kem_types::parse_pkinit_hint(hint_der)?;

        if oids.is_empty() {
            return Ok(());
        }

        if let Some(current_kem) = self.config.kem_algorithm
            && oids.iter().any(|oid| oid.as_slice() == current_kem.oid())
        {
            return Ok(());
        }

        for oid in &oids {
            if let Some(kem_alg) = KemAlgorithm::from_oid(oid) {
                self.config.kem_algorithm = Some(kem_alg);
                self.kem_key = None;
                return Ok(());
            }
        }

        Ok(())
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

        let sha256_alg_id = synta_krb5::pkinit::AlgorithmIdentifier {
            algorithm: synta::ObjectIdentifier::new(synta_certificate::oids::ID_SHA256)
                .map_err(asn1_err("SHA-256 OID"))?,
            parameters: None,
        };
        let pa_checksum2 = synta_krb5::pkinit::PAChecksum2 {
            checksum: OctetStringRef::new(&checksums.sha256),
            algorithm_identifier: sha256_alg_id,
        };
        let pk_auth = synta_krb5::pkinit::PKAuthenticator {
            cusec: synta::Integer::from(cusec),
            ctime: gen_time,
            nonce: synta::Integer::from(nonce),
            pa_checksum: Some(OctetStringRef::new(&checksums.sha1)),
            freshness_token: freshness_ref.map(OctetStringRef::new),
            pa_checksum2: Some(pa_checksum2),
        };

        let use_kem = self.config.kem_algorithm.is_some();

        let client_spki_der = if use_kem {
            let kem_alg = self.config.kem_algorithm.unwrap();
            self.key_exchange = Some(KeyExchangeType::Kem(kem_alg));
            if self.kem_key.is_none() {
                self.kem_key = Some(KemKeyPair::generate(kem_alg)?);
            }
            self.kem_key.as_ref().unwrap().public_key_spki_der()?
        } else {
            self.key_exchange = Some(KeyExchangeType::Dh(self.config.dh_group));
            if self.dh_key.is_none() {
                self.dh_key = Some(DhKeyPair::generate(self.config.dh_group)?);
            }
            self.dh_key.as_ref().unwrap().public_key_spki_der()?
        };

        let client_spki_element: synta::Element<'_> =
            synta::Decoder::new(&client_spki_der, synta::Encoding::Der)
                .decode()
                .map_err(asn1_err("decode SPKI element"))?;

        let dh_nonce_bytes = if use_kem {
            None
        } else {
            let nonce = native_ossl::rand::Rand::bytes(32)
                .map_err(|e| PkinitError::Ossl(format!("random bytes: {e}")))?;
            self.dh_nonce = Some(nonce.clone());
            Some(nonce)
        };

        let supported_kdfs = if use_kem {
            vec![synta_krb5::pkinit::KDFAlgorithmId {
                kdf_id: synta::ObjectIdentifier::new(constants::ID_ALG_HKDF_WITH_SHA512)
                    .map_err(asn1_err("KDF OID"))?,
            }]
        } else {
            vec![
                synta_krb5::pkinit::KDFAlgorithmId {
                    kdf_id: synta::ObjectIdentifier::new(constants::ID_PKINIT_KDF_AH_SHA256)
                        .map_err(asn1_err("KDF OID"))?,
                },
                synta_krb5::pkinit::KDFAlgorithmId {
                    kdf_id: synta::ObjectIdentifier::new(constants::ID_PKINIT_KDF_AH_SHA512)
                        .map_err(asn1_err("KDF OID"))?,
                },
                synta_krb5::pkinit::KDFAlgorithmId {
                    kdf_id: synta::ObjectIdentifier::new(constants::ID_PKINIT_KDF_AH_SHA1)
                        .map_err(asn1_err("KDF OID"))?,
                },
            ]
        };

        let auth_pack = synta_krb5::pkinit::AuthPack {
            pk_authenticator: pk_auth,
            client_public_value: Some(client_spki_element),
            supported_cmstypes: None,
            client_dhnonce: dh_nonce_bytes.as_ref().map(|b| OctetStringRef::new(b)),
            supported_kdfs: Some(supported_kdfs),
        };

        let auth_pack_der = auth_pack.to_der().map_err(asn1_err("encode AuthPack"))?;

        let signed_auth_pack = if self.identity.cert_der.is_empty() {
            cms::create_unsigned_data(&auth_pack_der, synta_krb5::pkinit::ID_PKINIT_AUTH_DATA)?
        } else {
            let signer_key = synta_certificate::crypto::BackendPrivateKey::from_pkcs8_der_unchecked(
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
            .map_err(asn1_err("encode PA-PK-AS-REQ"))
    }

    pub fn process_as_rep(
        &mut self,
        pa_rep_der: &[u8],
        params: &AsRepParams<'_>,
        o2k: &dyn OctetString2Key,
    ) -> Result<DerivedKey, PkinitError> {
        if crate::kem_types::is_kem_rep(pa_rep_der) {
            return self.process_kem_rep(pa_rep_der, params, o2k);
        }

        let pa_rep: synta_krb5::pkinit::PaPkAsRep<'_> =
            synta_krb5::pkinit::PaPkAsRep::from_der(pa_rep_der)
                .map_err(asn1_err("decode PA-PK-AS-REP"))?;

        match pa_rep {
            synta_krb5::pkinit::PaPkAsRep::DhInfo(dh_rep_info) => {
                self.process_dh_rep(dh_rep_info, params, o2k)
            }
            synta_krb5::pkinit::PaPkAsRep::EncKeyPack(_) => Err(PkinitError::Unsupported(
                "RSA key transport mode not supported".into(),
            )),
        }
    }

    fn process_dh_rep(
        &mut self,
        dh_rep_info: synta_krb5::pkinit::DHRepInfo<'_>,
        params: &AsRepParams<'_>,
        o2k: &dyn OctetString2Key,
    ) -> Result<DerivedKey, PkinitError> {
        let nonce = params.nonce;
        let enctype = params.enctype;
        let as_req_der = params.as_req_der;
        let client_name = params.client_name;
        let server_name = params.server_name;
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
                .map_err(asn1_err("decode KDCDHKeyInfo"))?;

        let reply_nonce = kdc_dh_key_info.nonce.as_i64().map_err(asn1_err("nonce"))?;
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

        let kdc_spki_der = rebuild_spki(dh_key.group(), kdc_pub_bits)?;

        let shared_secret = dh_key.derive_shared_secret(&kdc_spki_der)?;

        let server_dh_nonce = dh_rep_info.server_dhnonce.map(|n| n.as_bytes().to_vec());
        let selected_kdf = dh_rep_info
            .kdf
            .as_ref()
            .map(|k| k.kdf_id.components().to_vec());

        if let Some(kdf_oid) = selected_kdf {
            let party_u = encode_principal_for_kdf(client_name)?;
            let party_v = encode_principal_for_kdf(server_name)?;

            kdf::pkinit_kdf(
                &kdf::KdfInput {
                    shared_secret: shared_secret.as_ref(),
                    kdf_oid: &kdf_oid,
                    enctype,
                    party_u_info: &party_u,
                    party_v_info: &party_v,
                    as_req_der,
                    pa_pk_as_rep_der: params.pa_rep_raw,
                },
                o2k,
            )
        } else {
            let mut combined_nonce = self.dh_nonce.clone().unwrap_or_default();
            if let Some(ref sn) = server_dh_nonce {
                combined_nonce.extend_from_slice(sn);
            }

            let mut combined = Vec::with_capacity(shared_secret.len() + combined_nonce.len());
            combined.extend_from_slice(shared_secret.as_ref());
            combined.extend_from_slice(&combined_nonce);
            let secret_with_nonce = native_ossl::util::SecretBuf::new(combined);

            kdf::octetstring2key(secret_with_nonce.as_ref(), enctype, o2k)
        }
    }

    fn process_kem_rep(
        &mut self,
        pa_rep_der: &[u8],
        params: &AsRepParams<'_>,
        o2k: &dyn OctetString2Key,
    ) -> Result<DerivedKey, PkinitError> {
        use crate::kem_types::{KdcKemInfo, KemRepInfo, decode_kem_rep_content};

        let kem_key = self.kem_key.take().ok_or_else(|| {
            PkinitError::KemDecapFailed("no KEM key generated for this exchange".into())
        })?;
        let kem_alg = kem_key.algorithm();

        let kem_rep_content = decode_kem_rep_content(pa_rep_der)?;
        let kem_rep_info =
            KemRepInfo::from_der(&kem_rep_content).map_err(asn1_err("decode KEMRepInfo"))?;

        let verified = cms::verify_signed_data(kem_rep_info.kem_signed_data.as_bytes())?;

        if verified.content_type.as_slice() != constants::ID_PKINIT_KEM_KEY_DATA {
            return Err(PkinitError::CmsContentTypeMismatch {
                expected: "id-pkinit-KEMKeyData".into(),
                actual: format!("{:?}", verified.content_type),
            });
        }

        if self.has_pq_certificate() && !is_pq_signature_algorithm(&verified.signer_algorithm_oid) {
            return Err(PkinitError::DowngradeRejected(
                "KDC must use quantum-resistant signature with PQ client".into(),
            ));
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

        let kdc_kem_info =
            KdcKemInfo::from_der(&verified.content).map_err(asn1_err("decode KDCKEMInfo"))?;

        if kdc_kem_info.server_nonce.is_some() {
            return Err(PkinitError::KemDecapFailed(
                "serverNonce must be absent for pure ML-KEM".into(),
            ));
        }

        let reply_nonce = kdc_kem_info
            .nonce
            .as_ref()
            .ok_or_else(|| PkinitError::Asn1("KDC omitted required nonce in KDCKEMInfo".into()))?;
        let n = reply_nonce.as_i64().map_err(asn1_err("nonce"))?;
        if n != params.nonce as i64 {
            return Err(PkinitError::NonceMismatch {
                expected: params.nonce,
                actual: n as i32,
            });
        }

        let reply_kem_oid = kdc_kem_info.kem_algorithm.algorithm.components();
        let expected_oid = kem_alg.oid();
        if reply_kem_oid != expected_oid {
            return Err(PkinitError::KemAlgorithmMismatch {
                expected: format!("{expected_oid:?}"),
                actual: format!("{reply_kem_oid:?}"),
            });
        }

        let kemct = kdc_kem_info.kemct.as_bytes();
        if kemct.len() != kem_alg.ciphertext_len() {
            return Err(PkinitError::KemCiphertextLengthInvalid {
                expected: kem_alg.ciphertext_len(),
                actual: kemct.len(),
            });
        }

        let shared_secret = kem_key.decapsulate(kemct)?;

        kdf::pkinit_kem_kdf(
            &kdf::KemKdfInput {
                shared_secret: shared_secret.as_ref(),
                enctype: params.enctype,
                as_req_der: params.as_req_der,
                kem_signed_data: kem_rep_info.kem_signed_data.as_bytes(),
            },
            o2k,
        )
    }

    pub fn handle_tryagain(&mut self, error_padata_der: &[u8]) -> Result<RetryAction, PkinitError> {
        let padata_list: Vec<synta_krb5::kerberos_v5::PaData> =
            synta::Decoder::new(error_padata_der, synta::Encoding::Der)
                .decode()
                .map_err(asn1_err("decode error padata"))?;

        for pa in &padata_list {
            let pa_type = pa.padata_type.get();

            if pa_type == synta_krb5::constants::TD_DH_PARAMETERS {
                let data = pa.padata_value.as_bytes();

                if let Some(kem_alg) = parse_td_kem_algorithm(data) {
                    self.kem_key = None;
                    self.config.kem_algorithm = Some(kem_alg);
                    return Ok(RetryAction::RetryWithKemAlgorithm(kem_alg));
                }

                if let Some(group) = parse_td_dh_parameters(data, self.config.dh_min_bits) {
                    if self.has_pq_certificate() {
                        return Err(PkinitError::DowngradeRejected(
                            "PQ client must not fall back to classical DH".into(),
                        ));
                    }
                    self.dh_key = None;
                    self.config.kem_algorithm = None;
                    return Ok(RetryAction::RetryWithDhParams(group));
                }

                return Err(PkinitError::KemAlgorithmNotSupported(
                    "no mutually acceptable key exchange parameters".into(),
                ));
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

fn parse_td_kem_algorithm(data: &[u8]) -> Option<KemAlgorithm> {
    let td: synta_krb5::pkinit::TdDhParameters<'_> =
        synta_krb5::pkinit::TdDhParameters::from_der(data).ok()?;

    for elem in td.0.iter() {
        let elem_der = elem.to_der().ok()?;
        let alg_id: synta_certificate::AlgorithmIdentifier<'_> =
            synta::Decoder::new(&elem_der, synta::Encoding::Der)
                .decode()
                .ok()?;
        if let Some(kem_alg) = KemAlgorithm::from_oid(alg_id.algorithm.components()) {
            return Some(kem_alg);
        }
    }
    None
}

fn parse_td_dh_parameters(data: &[u8], min_bits: u32) -> Option<DhGroup> {
    let td: synta_krb5::pkinit::TdDhParameters<'_> =
        synta_krb5::pkinit::TdDhParameters::from_der(data).ok()?;

    for elem in td.0.iter() {
        let elem_der = elem.to_der().ok()?;
        if let Ok(group) = dh::validate_dh_params(&elem_der, min_bits) {
            return Some(group);
        }
    }
    None
}

/// Rebuild the KDC's SubjectPublicKeyInfo for `group` from its raw public
/// key bits, so `DhKeyPair::derive_shared_secret` can consume it — the KDC's
/// `KDCDHKeyInfo.subjectPublicKey` carries only the bare key, not a full
/// SPKI, per {{RFC4556}} Section 3.2.3.1.
fn rebuild_spki(group: DhGroup, pub_key_bits: &[u8]) -> Result<Vec<u8>, PkinitError> {
    let (algorithm, parameters) = dh::group_algorithm_oid_and_params(group)?;

    let alg_id = synta_krb5::kerberos_v5_pkinit_agility::AlgorithmIdentifier {
        algorithm: synta::ObjectIdentifier::new(algorithm).map_err(asn1_err("algorithm OID"))?,
        parameters,
    };

    let spki = synta_krb5::kerberos_v5_pkinit_agility::SubjectPublicKeyInfo {
        algorithm: alg_id,
        subject_public_key: synta::BitString::new(pub_key_bits.to_vec(), 0)
            .map_err(asn1_err("BitString"))?,
    };

    spki.to_der().map_err(asn1_err("encode SPKI"))
}

fn is_pq_signature_algorithm(oid: &[u32]) -> bool {
    oid == constants::ID_ML_DSA_44
        || oid == constants::ID_ML_DSA_65
        || oid == constants::ID_ML_DSA_87
}

pub fn is_pq_signing_certificate(cert_der: &[u8]) -> bool {
    let cert = match synta_certificate::Certificate::from_der(cert_der) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let sig_alg_oid = cert.tbs_certificate.signature.algorithm.components();
    is_pq_signature_algorithm(sig_alg_oid)
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
    fn process_pkinit_hint_selects_kem() {
        let mut state = PkinitClientState::new(
            PkinitIdentity {
                cert_der: vec![],
                key_pkcs8_der: vec![],
                chain: vec![],
            },
            TrustStore::new(),
            PkinitClientConfig::default(),
        );
        assert!(state.config.kem_algorithm.is_none());

        let hint_der =
            crate::kem_types::encode_pkinit_hint(&[crate::constants::ID_ML_KEM_768]).unwrap();
        state.process_pkinit_hint(&hint_der).unwrap();
        assert_eq!(state.config.kem_algorithm, Some(KemAlgorithm::MlKem768));
    }

    #[test]
    fn process_pkinit_hint_keeps_matching_kem() {
        let mut config = PkinitClientConfig::default();
        config.kem_algorithm = Some(KemAlgorithm::MlKem1024);
        let mut state = PkinitClientState::new(
            PkinitIdentity {
                cert_der: vec![],
                key_pkcs8_der: vec![],
                chain: vec![],
            },
            TrustStore::new(),
            config,
        );

        let hint_der = crate::kem_types::encode_pkinit_hint(&[
            crate::constants::ID_ML_KEM_768,
            crate::constants::ID_ML_KEM_1024,
        ])
        .unwrap();
        state.process_pkinit_hint(&hint_der).unwrap();
        assert_eq!(state.config.kem_algorithm, Some(KemAlgorithm::MlKem1024));
    }

    #[test]
    fn process_pkinit_hint_empty_is_noop() {
        let mut state = PkinitClientState::new(
            PkinitIdentity {
                cert_der: vec![],
                key_pkcs8_der: vec![],
                chain: vec![],
            },
            TrustStore::new(),
            PkinitClientConfig::default(),
        );
        let hint_der = crate::kem_types::encode_pkinit_hint(&[]).unwrap();
        state.process_pkinit_hint(&hint_der).unwrap();
        assert!(state.config.kem_algorithm.is_none());
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
        let empty_der = empty.to_der().expect("encode empty padata list");
        let result = state.handle_tryagain(&empty_der).unwrap();
        assert!(matches!(result, RetryAction::NoRetry));
    }
}
