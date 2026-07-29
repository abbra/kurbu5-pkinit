use synta::{OctetStringRef, ToDer};

use crate::certauth;
use crate::config::PkinitKdcConfig;
use crate::constants::DhGroup;
use crate::crypto::checksum;
use crate::crypto::cms;
use crate::crypto::dh::{self, DhKeyPair};
use crate::crypto::kdf::{self, DerivedKey, OctetString2Key, encode_principal_for_kdf};
use crate::error::PkinitError;
use crate::identity::{PkinitIdentity, TrustStore};

pub struct VerifiedRequest {
    pub client_cert_der: Vec<u8>,
    pub client_dh_public: Vec<u8>,
    pub nonce: i32,
    pub supported_kdfs: Vec<Vec<u32>>,
    pub client_dh_nonce: Option<Vec<u8>>,
    pub is_anonymous: bool,
    pub dh_group: DhGroup,
}

pub struct PkinitKdcState {
    identity: PkinitIdentity,
    trust_store: TrustStore,
    config: PkinitKdcConfig,
}

impl PkinitKdcState {
    pub fn new(
        identity: PkinitIdentity,
        trust_store: TrustStore,
        config: PkinitKdcConfig,
    ) -> Self {
        Self {
            identity,
            trust_store,
            config,
        }
    }

    pub fn verify_as_req(
        &self,
        pa_req_der: &[u8],
        req_body_der: Option<&[u8]>,
        max_skew: i64,
        current_time: i64,
        _freshness_token: Option<&[u8]>,
    ) -> Result<VerifiedRequest, PkinitError> {
        let pa_req: synta_krb5::pkinit::PaPkAsReq<'_> =
            synta_krb5::pkinit::PaPkAsReq::from_der(pa_req_der)
                .map_err(|e| PkinitError::Asn1(format!("decode PA-PK-AS-REQ: {e}")))?;

        let verified_cms = cms::verify_signed_data(pa_req.signed_auth_pack.as_bytes());

        let (auth_pack_der, client_cert_der, is_anonymous) = match verified_cms {
            Ok(v) => {
                if v.content_type.as_slice() != synta_krb5::pkinit::ID_PKINIT_AUTH_DATA {
                    return Err(PkinitError::CmsContentTypeMismatch {
                        expected: "id-pkinit-authData".into(),
                        actual: format!("{:?}", v.content_type),
                    });
                }

                self.trust_store.validate_chain(
                    &v.signer_cert_der,
                    &v.all_certs_der,
                    self.config.require_crl_checking,
                )?;

                if self.config.require_eku {
                    let eku_result = certauth::verify_client_eku(
                        &v.signer_cert_der,
                        self.config.accept_secondary_eku,
                    )?;
                    if matches!(eku_result, certauth::CertauthResult::Rejected(_)) {
                        return Err(PkinitError::EkuMismatch("client EKU check failed".into()));
                    }
                }

                (v.content, v.signer_cert_der, false)
            }
            Err(_) => {
                let raw = pa_req.signed_auth_pack.as_bytes();
                let auth_pack_der = match cms::extract_unsigned_content(raw) {
                    Ok((content, ct)) => {
                        if ct.as_slice() != synta_krb5::pkinit::ID_PKINIT_AUTH_DATA {
                            return Err(PkinitError::CmsContentTypeMismatch {
                                expected: "id-pkinit-authData".into(),
                                actual: format!("{ct:?}"),
                            });
                        }
                        content
                    }
                    Err(_) => raw.to_vec(),
                };
                (auth_pack_der, vec![], true)
            }
        };

        let auth_pack: synta_krb5::pkinit::AuthPack<'_> =
            synta_krb5::pkinit::AuthPack::from_der(&auth_pack_der)
                .map_err(|e| PkinitError::Asn1(format!("decode AuthPack: {e}")))?;

        let pk_auth = &auth_pack.pk_authenticator;

        let client_time = pk_auth.ctime.to_unix();
        let time_diff = (client_time - current_time).abs();
        if time_diff > max_skew {
            return Err(PkinitError::ClockSkew {
                client_time,
                max_skew,
            });
        }

        let pa_checksum2_info = pk_auth.pa_checksum2.as_ref().map(|pc2| {
            (
                pc2.checksum.as_bytes(),
                pc2.algorithm_identifier.algorithm.components(),
            )
        });

        if let Some(body) = req_body_der {
            if let Some(pa_checksum) = pk_auth.pa_checksum.as_ref() {
                checksum::verify_checksums(body, pa_checksum.as_bytes(), pa_checksum2_info)?;
            } else if let Some((checksum2_bytes, oid)) = pa_checksum2_info {
                checksum::verify_checksum2(body, checksum2_bytes, oid)?;
            }
        }

        let client_dh_public = auth_pack
            .client_public_value
            .as_ref()
            .ok_or_else(|| {
                PkinitError::DhParamsRejected("missing client DH public value".into())
            })?
            .to_der()
            .map_err(|e| PkinitError::Asn1(format!("encode client SPKI: {e}")))?;

        let dh_group = dh::validate_dh_params(&client_dh_public, self.config.dh_min_bits)?;

        let nonce = pk_auth
            .nonce
            .as_i64()
            .map_err(|e| PkinitError::Asn1(format!("nonce: {e}")))?
            as i32;

        let client_dh_nonce = auth_pack
            .client_dhnonce
            .as_ref()
            .map(|n| n.as_bytes().to_vec());

        let supported_kdfs = auth_pack
            .supported_kdfs
            .as_ref()
            .map(|kdfs| {
                kdfs.iter()
                    .map(|k| k.kdf_id.components().to_vec())
                    .collect()
            })
            .unwrap_or_default();

        Ok(VerifiedRequest {
            client_cert_der,
            client_dh_public,
            nonce,
            supported_kdfs,
            client_dh_nonce,
            is_anonymous,
            dh_group,
        })
    }

    pub fn build_as_rep(
        &self,
        verified: &VerifiedRequest,
        nonce: i32,
        enctype: i32,
        as_req_der: &[u8],
        client_name: &str,
        server_name: &str,
        o2k: &dyn OctetString2Key,
    ) -> Result<(Vec<u8>, DerivedKey), PkinitError> {
        let kdc_dh_key = DhKeyPair::generate(verified.dh_group)?;
        let kdc_spki_der = kdc_dh_key.public_key_spki_der()?;

        let shared_secret = kdc_dh_key.derive_shared_secret(&verified.client_dh_public)?;

        let kdc_pub_bits = extract_pub_key_bits(&kdc_spki_der)?;

        let kdc_dh_key_info = synta_krb5::pkinit::KDCDHKeyInfo {
            subject_public_key: synta::BitStringRef::new(&kdc_pub_bits, 0)
                .map_err(|e| PkinitError::Asn1(format!("BitStringRef: {e}")))?,
            nonce: synta::Integer::from(nonce),
            dh_key_expiration: None,
        };

        let kdc_dh_key_info_der = kdc_dh_key_info
            .to_der()
            .map_err(|e| PkinitError::Asn1(format!("encode KDCDHKeyInfo: {e}")))?;

        let signer_key =
            synta_certificate::crypto::BackendPrivateKey::from_pkcs8_der_unchecked(
                self.identity.key_pkcs8_der.clone(),
            );
        let extra_certs: Vec<&[u8]> = self.identity.chain.iter().map(|c| c.as_slice()).collect();

        let signed_kdc_dh = cms::create_signed_data(
            &kdc_dh_key_info_der,
            synta_krb5::pkinit::ID_PKINIT_DHKEY_DATA,
            &signer_key,
            &self.identity.cert_der,
            &extra_certs,
            "sha256",
        )?;

        let server_dh_nonce = native_ossl::rand::Rand::bytes(32)
            .map_err(|e| PkinitError::Ossl(format!("random bytes: {e}")))?;

        let selected_kdf = kdf::pick_kdf_alg(&verified.supported_kdfs);

        let kdf_alg_id = selected_kdf.map(|oid| {
            synta_krb5::pkinit::KDFAlgorithmId {
                kdf_id: synta::ObjectIdentifier::new(oid).unwrap(),
            }
        });

        let dh_rep_info = synta_krb5::pkinit::DHRepInfo {
            dh_signed_data: OctetStringRef::new(&signed_kdc_dh),
            server_dhnonce: Some(OctetStringRef::new(&server_dh_nonce)),
            kdf: kdf_alg_id,
        };

        let pa_rep = synta_krb5::pkinit::PaPkAsRep::DhInfo(dh_rep_info);
        let pa_rep_der = pa_rep
            .to_der()
            .map_err(|e| PkinitError::Asn1(format!("encode PA-PK-AS-REP: {e}")))?;

        let derived_key = if let Some(kdf_oid) = selected_kdf {
            let party_u = encode_principal_for_kdf(client_name)?;
            let party_v = encode_principal_for_kdf(server_name)?;

            kdf::pkinit_kdf(
                &shared_secret,
                kdf_oid,
                enctype,
                &party_u,
                &party_v,
                as_req_der,
                &pa_rep_der,
                o2k,
            )?
        } else {
            let mut combined_nonce = verified.client_dh_nonce.clone().unwrap_or_default();
            combined_nonce.extend_from_slice(&server_dh_nonce);

            let mut secret_with_nonce = shared_secret;
            secret_with_nonce.extend_from_slice(&combined_nonce);

            kdf::octetstring2key(&secret_with_nonce, enctype, o2k)?
        };

        Ok((pa_rep_der, derived_key))
    }
}

fn extract_pub_key_bits(spki_der: &[u8]) -> Result<Vec<u8>, PkinitError> {
    let spki: synta_krb5::kerberos_v5_pkinit_agility::SubjectPublicKeyInfo<'_> =
        synta::Decoder::new(spki_der, synta::Encoding::Der)
            .decode()
            .map_err(|e| PkinitError::Asn1(format!("decode SPKI: {e}")))?;
    Ok(spki.subject_public_key.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::PkinitClientState;
    use crate::config::{PkinitClientConfig, PkinitKdcConfig};
    use crate::constants;

    struct MockO2K;
    impl crate::crypto::kdf::OctetString2Key for MockO2K {
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
            CertificateBuilder, ExtendedKeyUsageBuilder, NameBuilder,
            SubjectAlternativeNameBuilder, Time,
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
            synta_certificate::crypto::BackendPrivateKey::from_pkcs8_der_unchecked(
                ca_pkcs8.clone(),
            );
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
            .add_extension_oid(synta_certificate::oids::SUBJECT_KEY_IDENTIFIER, false, &ski_der)
            .add_extension_oid(synta_certificate::oids::AUTHORITY_KEY_IDENTIFIER, false, &aki_der)
            .add_extension_oid(synta_certificate::oids::BASIC_CONSTRAINTS, true, &bc_der)
            .sign(&ca_signer)
            .unwrap();

        let make_identity =
            |cn: &str, san_oid_data: Vec<u8>, eku_oid: &[u32]| -> PkinitIdentity {
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
                    .serial_number(Integer::from_i64(2))
                    .not_valid_before(Time::UtcTime(
                        UtcTime::new(2025, 1, 1, 0, 0, 0).unwrap(),
                    ))
                    .not_valid_after(Time::UtcTime(
                        UtcTime::new(2027, 1, 1, 0, 0, 0).unwrap(),
                    ))
                    .add_extension_oid(
                        synta_certificate::oids::SUBJECT_ALT_NAME,
                        false,
                        &san_der,
                    )
                    .add_extension_oid(
                        synta_certificate::oids::EXTENDED_KEY_USAGE,
                        false,
                        &eku_der,
                    )
                    .add_extension_oid(
                        synta_certificate::oids::KEY_USAGE,
                        true,
                        &ku_der,
                    )
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

        let client_san =
            synta_krb5::principal::encode_krb5_san("testuser", "EXAMPLE.COM").unwrap();
        let client_id = make_identity(
            "Test Client",
            client_san,
            constants::ID_PKINIT_KPCLIENT_AUTH,
        );

        let kdc_san =
            synta_krb5::principal::encode_krb5_san("krbtgt/EXAMPLE.COM", "EXAMPLE.COM").unwrap();
        let kdc_id = make_identity("Test KDC", kdc_san, constants::ID_PKINIT_KPKDC);

        let mut trust_store = TrustStore::new();
        trust_store.add_anchor(ca_cert_der);

        (client_id, kdc_id, trust_store)
    }

    #[test]
    fn kdc_state_construction() {
        let (_, kdc_id, trust_store) = generate_test_pki();
        let state = PkinitKdcState::new(kdc_id, trust_store, PkinitKdcConfig::default());
        assert!(state.config.require_eku);
    }

    #[test]
    fn full_pkinit_dh_exchange() {
        let (client_id, kdc_id, trust_store) = generate_test_pki();
        let o2k = MockO2K;

        let mut client_config = PkinitClientConfig::default();
        client_config.dh_group = DhGroup::EcP256;
        let mut client =
            PkinitClientState::new(client_id, trust_store.clone(), client_config);
        client.set_kdc_identity(
            "krbtgt/EXAMPLE.COM@EXAMPLE.COM".to_string(),
            None,
        );

        let server = PkinitKdcState::new(kdc_id, trust_store, PkinitKdcConfig::default());

        let req_body_der = b"mock-req-body";
        let ctime = 1719600000i64;
        let pa_req = client
            .build_as_req(12345, ctime, 0, req_body_der)
            .unwrap();

        let verified = server
            .verify_as_req(&pa_req, Some(req_body_der), 300, ctime, None)
            .unwrap();
        assert!(!verified.is_anonymous);

        let as_req_der = b"mock-full-as-req";
        let client_name = "testuser@EXAMPLE.COM";
        let server_name = "krbtgt/EXAMPLE.COM@EXAMPLE.COM";
        let (pa_rep, server_key) = server
            .build_as_rep(
                &verified,
                12345,
                18,
                as_req_der,
                client_name,
                server_name,
                &o2k,
            )
            .unwrap();

        let client_key = client
            .process_as_rep(
                &pa_rep,
                12345,
                18,
                as_req_der,
                &pa_rep,
                client_name,
                server_name,
                &o2k,
            )
            .unwrap();

        assert_eq!(client_key.enctype, server_key.enctype);
        assert_eq!(client_key.key_data, server_key.key_data);
    }
}
