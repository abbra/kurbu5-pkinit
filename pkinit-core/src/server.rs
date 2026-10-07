use synta::{OctetStringRef, ToDer};

use crate::certauth;
use crate::config::PkinitKdcConfig;
pub use crate::constants::KeyExchangeType;
use crate::constants::{DhGroup, KemAlgorithm};
use crate::crypto::checksum;
use crate::crypto::cms;
use crate::crypto::dh::{self, DhKeyPair};
use crate::crypto::kdf::{self, DerivedKey, OctetString2Key, encode_principal_for_kdf};
use crate::error::{PkinitError, asn1_err};
use crate::identity::{PkinitIdentity, TrustStore};

#[derive(Debug)]
pub struct VerifiedRequest {
    pub client_cert_der: Vec<u8>,
    pub client_dh_public: Vec<u8>,
    pub nonce: i32,
    pub supported_kdfs: Vec<Vec<u32>>,
    pub client_dh_nonce: Option<Vec<u8>>,
    pub is_anonymous: bool,
    pub key_exchange: KeyExchangeType,
}

pub struct BuildAsRepParams<'a> {
    pub nonce: i32,
    pub enctype: i32,
    pub as_req_der: &'a [u8],
    pub client_name: &'a str,
    pub server_name: &'a str,
}

pub struct PkinitKdcState {
    identity: PkinitIdentity,
    trust_store: TrustStore,
    config: PkinitKdcConfig,
    /// Cache of [`Self::build_supported_algorithms_hint`]'s result: `config`
    /// never changes after construction, so this DER blob is the same on
    /// every call and would otherwise be redundantly rebuilt (OID
    /// validation, ASN.1 encoding) on every AS-REQ lacking PA-DATA.
    supported_algorithms_hint: Option<Vec<u8>>,
    /// Cache of [`Self::build_td_ephemeral_key_params`]'s result, for the
    /// same reason — rebuilt otherwise on every rejected AS-REQ.
    td_ephemeral_key_params: Vec<u8>,
}

impl PkinitKdcState {
    pub fn new(
        identity: PkinitIdentity,
        trust_store: TrustStore,
        mut config: PkinitKdcConfig,
    ) -> Result<Self, PkinitError> {
        // require_kem without a KEM floor: make the implicit "any ML-KEM"
        // explicit, so it is advertised in the hint and in the typed data
        // that replaces the (refused) DH/ECDH groups.
        if config.require_kem
            && config.supported_kem_algorithms.is_empty()
            && config.supported_composite_kem_algorithms.is_empty()
        {
            config.supported_kem_algorithms = KemAlgorithm::MlKem512.algorithms_at_or_above();
        }
        let supported_algorithms_hint = build_supported_algorithms_hint(&config)?;
        let td_ephemeral_key_params = build_td_ephemeral_key_params(&config)?;
        Ok(Self {
            identity,
            trust_store,
            config,
            supported_algorithms_hint,
            td_ephemeral_key_params,
        })
    }

    /// Proactive advertisement (`PA-PK-AS-REQ-Hint.ephemeralKeyParameters`,
    /// {{sec-proactive-adv}}): every key-establishment algorithm this KDC
    /// accepts, in decreasing order of preference -- the same list as
    /// [`Self::build_td_ephemeral_key_params`]. A client that implements none
    /// of them must fail rather than try an unadvertised algorithm
    /// ({{sec-client-alg-selection}}), so omitting an accepted algorithm
    /// (such as the DH/ECDH groups) would turn such clients away.
    ///
    /// `None` when the KDC accepts nothing it could advertise (no KEM and a
    /// `dh_min_bits` above every group); the KDC then sends the empty
    /// padata-value of {{RFC4556}} Section 3.4.
    pub fn build_supported_algorithms_hint(&self) -> Option<Vec<u8>> {
        self.supported_algorithms_hint.clone()
    }

    /// `TD-EPHEMERAL-KEY-PARAMETERS-DATA` ({{sec-ephemeral-key-errors}}):
    /// every key-establishment algorithm this KDC currently accepts — KEM,
    /// composite KEM, and DH/ECDH groups at or above `dh_min_bits` — each
    /// with real parameters so the client's retry logic
    /// (`PkinitClientState::handle_tryagain`) can act on them directly, per
    /// {{RFC4556}} Section 3.2.2.
    pub fn build_td_ephemeral_key_params(&self) -> Vec<u8> {
        self.td_ephemeral_key_params.clone()
    }

    /// Whether this KDC currently accepts `alg` on the KEM path.  Composite
    /// variants are explicit opt-in (`supported_composite_kem_algorithms`);
    /// pure ML-KEM keeps its pre-existing behavior of accepting any
    /// recognized algorithm when no floor is configured.
    fn accepts_kem(&self, alg: KemAlgorithm) -> bool {
        if alg.is_composite() {
            self.config
                .supported_composite_kem_algorithms
                .contains(&alg)
        } else {
            self.config.supported_kem_algorithms.is_empty()
                || self.config.supported_kem_algorithms.contains(&alg)
        }
    }

    pub fn verify_as_req(
        &self,
        pa_req_der: &[u8],
        req_body_der: Option<&[u8]>,
        max_skew: i64,
        current_time: i64,
    ) -> Result<VerifiedRequest, PkinitError> {
        let pa_req: synta_krb5::pkinit::PaPkAsReq<'_> =
            synta_krb5::pkinit::PaPkAsReq::from_der(pa_req_der)
                .map_err(asn1_err("decode PA-PK-AS-REQ"))?;

        let signed_auth_pack = pa_req.signed_auth_pack.as_bytes();

        // An unsigned AuthPack (anonymous PKINIT, {{RFC8062}}) is recognized
        // structurally: a SignedData with no SignerInfo, or a bare
        // ContentInfo. Anything else is a signed request, and a signature
        // that fails to verify is KDC_ERR_INVALID_SIG ({{RFC4556}} Section
        // 3.2.2) -- never a fallback to the anonymous path. Whether the
        // requested client principal may use an unsigned AuthPack at all is
        // the plugin's decision (it alone knows the principal).
        let unsigned = cms::extract_unsigned_content(signed_auth_pack)
            .or_else(|_| cms::extract_bare_content(signed_auth_pack))
            .ok();

        let (auth_pack_der, client_cert_der, is_anonymous) = match unsigned {
            Some((content, ct)) => {
                if ct.as_slice() != synta_krb5::pkinit::ID_PKINIT_AUTH_DATA {
                    return Err(PkinitError::CmsContentTypeMismatch {
                        expected: "id-pkinit-authData".into(),
                        actual: format!("{ct:?}"),
                    });
                }
                (content, vec![], true)
            }
            None => {
                let v = cms::verify_signed_data(signed_auth_pack)?;
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
        };

        let auth_pack: synta_krb5::pkinit::AuthPack<'_> =
            synta_krb5::pkinit::AuthPack::from_der(&auth_pack_der)
                .map_err(asn1_err("decode AuthPack"))?;

        let pk_auth = &auth_pack.pk_authenticator;

        let client_time = pk_auth.ctime.to_unix();
        let time_diff = (client_time - current_time).abs();
        if time_diff > max_skew {
            return Err(PkinitError::ClockSkew {
                client_time,
                max_skew,
            });
        }

        if self.config.require_freshness && pk_auth.freshness_token.is_none() {
            return Err(PkinitError::Config(
                "freshness token required but not provided by client".into(),
            ));
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
            .ok_or_else(|| PkinitError::DhParamsRejected("missing client DH public value".into()))?
            .to_der()
            .map_err(asn1_err("encode client SPKI"))?;

        let key_exchange = match detect_spki_algorithm(&client_dh_public)? {
            Some(kem_alg) => {
                if !self.accepts_kem(kem_alg) {
                    return Err(PkinitError::KemAlgorithmNotSupported(
                        kem_alg.parameter_set_name().into(),
                    ));
                }
                if auth_pack.client_dhnonce.is_some() {
                    return Err(PkinitError::KemNonceNotAllowed);
                }
                KeyExchangeType::Kem(kem_alg)
            }
            None if self.config.require_kem => {
                return Err(PkinitError::DhParamsRejected(
                    "classic DH/ECDH key exchange refused: pkinit_require_kem is set".into(),
                ));
            }
            None => KeyExchangeType::Dh(dh::validate_dh_params(
                &client_dh_public,
                self.config.dh_min_bits,
            )?),
        };

        let nonce = crate::kem_types::decode_nonce(&pk_auth.nonce)?;

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
            key_exchange,
        })
    }

    pub fn build_as_rep(
        &self,
        verified: &VerifiedRequest,
        params: &BuildAsRepParams<'_>,
        o2k: &dyn OctetString2Key,
    ) -> Result<(Vec<u8>, DerivedKey), PkinitError> {
        match verified.key_exchange {
            KeyExchangeType::Dh(dh_group) => self.build_dh_rep(verified, params, o2k, dh_group),
            KeyExchangeType::Kem(kem_alg) => self.build_kem_rep(verified, params, o2k, kem_alg),
        }
    }

    fn build_kem_rep(
        &self,
        verified: &VerifiedRequest,
        params: &BuildAsRepParams<'_>,
        o2k: &dyn OctetString2Key,
        kem_alg: KemAlgorithm,
    ) -> Result<(Vec<u8>, DerivedKey), PkinitError> {
        use crate::crypto::kem;
        use crate::kem_types::{KdcKemInfo, KemRepInfo, encode_kem_rep_wrapper};
        use synta::OctetString;

        // {{sec-kdf-oids}} / {{sec-kdc-response}} step 3: only HKDF-SHA-512 is
        // approved for the KEM path. If the client sent supportedKDFs but it
        // doesn't include the approved KDF, the KDC must not silently
        // substitute one; RFC 8636's KDC_ERR_NO_ACCEPTABLE_KDF applies. An
        // absent supportedKDFs defaults to HKDF-SHA-512 (nothing to check).
        if !verified.supported_kdfs.is_empty()
            && !verified
                .supported_kdfs
                .iter()
                .any(|kdf| kdf.as_slice() == crate::constants::ID_ALG_HKDF_WITH_SHA512)
        {
            return Err(PkinitError::NoAcceptableKdf);
        }

        let (kemct, shared_secret) =
            kem::encapsulate_for_client(&verified.client_dh_public, kem_alg)?;

        let kem_oid = synta::ObjectIdentifier::new(kem_alg.oid()).map_err(asn1_err("KEM OID"))?;
        let kdf_oid = synta::ObjectIdentifier::new(crate::constants::ID_ALG_HKDF_WITH_SHA512)
            .map_err(asn1_err("KDF OID"))?;

        let kdc_kem_info = KdcKemInfo {
            kem_algorithm: synta_certificate::AlgorithmIdentifier {
                algorithm: kem_oid,
                parameters: None,
            },
            kemct: OctetString::new(kemct),
            kdf_algorithm: synta_certificate::AlgorithmIdentifier {
                algorithm: kdf_oid,
                parameters: None,
            },
            nonce: Some(crate::kem_types::encode_nonce(params.nonce)),
            server_nonce: None,
        };

        let kdc_kem_info_der = kdc_kem_info
            .to_der()
            .map_err(asn1_err("encode KDCKEMInfo"))?;

        let signer_key = self.identity.signing_key.as_ref().ok_or_else(|| {
            PkinitError::IdentityLoadFailed("KDC identity has no signing key".into())
        })?;
        let extra_certs: Vec<&[u8]> = self.identity.chain.iter().map(|c| c.as_slice()).collect();

        let kem_signed_data = cms::create_signed_data(
            &kdc_kem_info_der,
            crate::constants::ID_PKINIT_KEM_KEY_DATA,
            signer_key,
            &self.identity.cert_der,
            &extra_certs,
            cms::digest_for_signer(&self.identity.cert_der),
        )?;

        let kem_rep_info = KemRepInfo {
            kem_signed_data: OctetString::new(kem_signed_data.clone()),
        };

        let pa_rep_der = encode_kem_rep_wrapper(&kem_rep_info)?;

        let derived_key = kdf::pkinit_kem_kdf(
            &kdf::KemKdfInput {
                shared_secret: shared_secret.as_ref(),
                enctype: params.enctype,
                as_req_der: params.as_req_der,
                kem_signed_data: &kem_signed_data,
            },
            o2k,
        )?;

        Ok((pa_rep_der, derived_key))
    }

    fn build_dh_rep(
        &self,
        verified: &VerifiedRequest,
        params: &BuildAsRepParams<'_>,
        o2k: &dyn OctetString2Key,
        dh_group: DhGroup,
    ) -> Result<(Vec<u8>, DerivedKey), PkinitError> {
        let nonce = params.nonce;
        let enctype = params.enctype;
        let as_req_der = params.as_req_der;
        let client_name = params.client_name;
        let server_name = params.server_name;
        let kdc_dh_key = DhKeyPair::generate(dh_group)?;
        let kdc_spki_der = kdc_dh_key.public_key_spki_der()?;

        let shared_secret = kdc_dh_key.derive_shared_secret(&verified.client_dh_public)?;

        let kdc_pub_bits = extract_pub_key_bits(&kdc_spki_der)?;

        let kdc_dh_key_info = synta_krb5::pkinit::KDCDHKeyInfo {
            subject_public_key: synta::BitStringRef::new(&kdc_pub_bits, 0)
                .map_err(asn1_err("BitStringRef"))?,
            nonce: crate::kem_types::encode_nonce(nonce),
            dh_key_expiration: None,
        };

        let kdc_dh_key_info_der = kdc_dh_key_info
            .to_der()
            .map_err(asn1_err("encode KDCDHKeyInfo"))?;

        let signer_key = self.identity.signing_key.as_ref().ok_or_else(|| {
            PkinitError::IdentityLoadFailed("KDC identity has no signing key".into())
        })?;
        let extra_certs: Vec<&[u8]> = self.identity.chain.iter().map(|c| c.as_slice()).collect();

        let signed_kdc_dh = cms::create_signed_data(
            &kdc_dh_key_info_der,
            synta_krb5::pkinit::ID_PKINIT_DHKEY_DATA,
            signer_key,
            &self.identity.cert_der,
            &extra_certs,
            cms::digest_for_signer(&self.identity.cert_der),
        )?;

        let server_dh_nonce = native_ossl::rand::Rand::bytes(32)
            .map_err(|e| PkinitError::Ossl(format!("random bytes: {e}")))?;

        let selected_kdf = kdf::pick_kdf_alg(&verified.supported_kdfs);

        let kdf_alg_id = selected_kdf.map(|oid| synta_krb5::pkinit::KDFAlgorithmId {
            kdf_id: synta::ObjectIdentifier::new(oid).unwrap(),
        });

        let dh_rep_info = synta_krb5::pkinit::DHRepInfo {
            dh_signed_data: OctetStringRef::new(&signed_kdc_dh),
            server_dhnonce: Some(OctetStringRef::new(&server_dh_nonce)),
            kdf: kdf_alg_id,
        };

        let pa_rep = synta_krb5::pkinit::PaPkAsRep::DhInfo(dh_rep_info);
        let pa_rep_der = pa_rep.to_der().map_err(asn1_err("encode PA-PK-AS-REP"))?;

        let derived_key = if let Some(kdf_oid) = selected_kdf {
            let party_u = encode_principal_for_kdf(client_name)?;
            let party_v = encode_principal_for_kdf(server_name)?;

            kdf::pkinit_kdf(
                &kdf::KdfInput {
                    shared_secret: shared_secret.as_ref(),
                    kdf_oid,
                    enctype,
                    party_u_info: &party_u,
                    party_v_info: &party_v,
                    as_req_der,
                    pa_pk_as_rep_der: &pa_rep_der,
                },
                o2k,
            )?
        } else {
            let mut combined_nonce = verified.client_dh_nonce.clone().unwrap_or_default();
            combined_nonce.extend_from_slice(&server_dh_nonce);

            let mut combined = Vec::with_capacity(shared_secret.len() + combined_nonce.len());
            combined.extend_from_slice(shared_secret.as_ref());
            combined.extend_from_slice(&combined_nonce);
            let secret_with_nonce = native_ossl::util::SecretBuf::new(combined);

            kdf::octetstring2key(secret_with_nonce.as_ref(), enctype, o2k)?
        };

        Ok((pa_rep_der, derived_key))
    }
}

fn build_supported_algorithms_hint(
    config: &PkinitKdcConfig,
) -> Result<Option<Vec<u8>>, PkinitError> {
    let alg_ids = acceptable_key_establishment_alg_ids(config)?;
    if alg_ids.is_empty() {
        return Ok(None);
    }
    crate::kem_types::encode_pkinit_hint_alg_ids(alg_ids).map(Some)
}

fn build_td_ephemeral_key_params(config: &PkinitKdcConfig) -> Result<Vec<u8>, PkinitError> {
    acceptable_key_establishment_alg_ids(config)?
        .to_der()
        .map_err(asn1_err("encode TD params"))
}

/// Every acceptable `AlgorithmIdentifier`, in decreasing order of preference
/// ({{sec-proactive-adv}}): post-quantum before classical, and stronger
/// before weaker within each family -- pure ML-KEM by NIST category, then
/// the configured composite KEMs, then EC curves and MODP groups at or above
/// `dh_min_bits` (none with `require_kem`). KEMs carry absent parameters
/// ({{sec-alg-id-encoding}}); DH groups and EC curves their real domain
/// parameters. Shared by the proactive hint and
/// [`build_td_ephemeral_key_params`].
fn acceptable_key_establishment_alg_ids(
    config: &PkinitKdcConfig,
) -> Result<Vec<synta_certificate::AlgorithmIdentifier<'static>>, PkinitError> {
    use synta::ObjectIdentifier;
    use synta_certificate::AlgorithmIdentifier;

    let mut pure_kems = config.supported_kem_algorithms.clone();
    pure_kems.sort_by_key(|alg| std::cmp::Reverse(alg.strength_order()));

    let kem_ids = pure_kems
        .iter()
        .chain(&config.supported_composite_kem_algorithms)
        .map(|alg| {
            let algorithm = ObjectIdentifier::new(alg.oid()).map_err(asn1_err("KEM OID"))?;
            Ok(AlgorithmIdentifier {
                algorithm,
                parameters: None,
            })
        });

    let group_ids = [
        DhGroup::EcP521,
        DhGroup::EcP384,
        DhGroup::EcP256,
        DhGroup::Oakley4096,
        DhGroup::Oakley2048,
    ]
    .into_iter()
    .filter(|group| !config.require_kem && group.min_bits() >= config.dh_min_bits)
    .map(group_algorithm_identifier);

    kem_ids.chain(group_ids).collect()
}

/// Build the `AlgorithmIdentifier` for a DH group or EC curve, carrying its
/// real domain parameters (the Oakley prime/generator, or the curve OID) so
/// a retrying client can validate it directly via `dh::validate_dh_params`.
fn group_algorithm_identifier(
    group: DhGroup,
) -> Result<synta_certificate::AlgorithmIdentifier<'static>, PkinitError> {
    let (algorithm, parameters) = dh::group_algorithm_oid_and_params(group)?;
    Ok(synta_certificate::AlgorithmIdentifier {
        algorithm: synta::ObjectIdentifier::new(algorithm).map_err(asn1_err("algorithm OID"))?,
        parameters,
    })
}

/// The KEM algorithm of a `clientPublicValue`, or `None` for a DH/ECDH (or
/// unrecognized) key. A KEM key must have absent algorithm parameters
/// ({{sec-alg-id-encoding}}); one that carries them is not accepted
/// (`KDC_ERR_EPHEMERAL_KEY_PARAMS_NOT_ACCEPTED`).
fn detect_spki_algorithm(spki_der: &[u8]) -> Result<Option<KemAlgorithm>, PkinitError> {
    let spki: synta_krb5::kerberos_v5_pkinit_agility::SubjectPublicKeyInfo<'_> =
        synta::Decoder::new(spki_der, synta::Encoding::Der)
            .decode()
            .map_err(asn1_err("decode SPKI"))?;
    let oid_components = spki.algorithm.algorithm.components();
    let Some(kem_alg) = KemAlgorithm::from_oid(oid_components) else {
        return Ok(None);
    };
    if spki.algorithm.parameters.is_some() {
        return Err(PkinitError::KemAlgorithmNotSupported(format!(
            "{} key with algorithm parameters (they must be absent)",
            kem_alg.parameter_set_name()
        )));
    }
    Ok(Some(kem_alg))
}

fn extract_pub_key_bits(spki_der: &[u8]) -> Result<Vec<u8>, PkinitError> {
    let spki: synta_krb5::kerberos_v5_pkinit_agility::SubjectPublicKeyInfo<'_> =
        synta::Decoder::new(spki_der, synta::Encoding::Der)
            .decode()
            .map_err(asn1_err("decode SPKI"))?;
    Ok(spki.subject_public_key.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::PkinitClientState;
    use crate::config::{PkinitClientConfig, PkinitKdcConfig};
    use crate::constants;
    use crate::test_support::{next_nonce, test_validity};

    struct MockO2K;
    impl crate::crypto::kdf::OctetString2Key for MockO2K {
        fn random_to_key(
            &self,
            enctype: i32,
            random_data: &[u8],
        ) -> Result<native_ossl::util::SecretBuf, PkinitError> {
            let len = self.key_length(enctype)?;
            let mut key = random_data.to_vec();
            key.resize(len, 0);
            Ok(native_ossl::util::SecretBuf::new(key[..len].to_vec()))
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
        use synta::Integer;
        use synta_certificate::{
            CertificateBuilder, ExtendedKeyUsageBuilder, NameBuilder,
            SubjectAlternativeNameBuilder, Time,
            crypto::{BackendPrivateKey, PrivateKey},
        };

        let ca_key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let ca_pkcs8 = ca_key.to_der().unwrap();
        let ca_spki = ca_key.public_key_spki_der().unwrap();
        let ca_name = NameBuilder::new()
            .common_name("Test PKINIT CA")
            .build()
            .unwrap();

        let ca_backend = BackendPrivateKey::from_pkcs8_der_unchecked(ca_pkcs8);
        let ca_signer = PrivateKey::as_signer(&ca_backend, "sha256");

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

        let (nb, na) = test_validity().expect("validity window");
        let ca_cert_der = CertificateBuilder::new()
            .subject_name(&ca_name)
            .issuer_name(&ca_name)
            .public_key_der(&ca_spki)
            .serial_number(Integer::from_i64(1))
            .not_valid_before(Time::UtcTime(nb))
            .not_valid_after(Time::UtcTime(na))
            .add_extension_oid(
                synta_certificate::oids::SUBJECT_KEY_IDENTIFIER,
                false,
                &ski_der,
            )
            .add_extension_oid(
                synta_certificate::oids::AUTHORITY_KEY_IDENTIFIER,
                false,
                &aki_der,
            )
            .add_extension_oid(synta_certificate::oids::BASIC_CONSTRAINTS, true, &bc_der)
            .sign(&ca_signer)
            .unwrap();

        let make_identity =
            |cn: &str, san_oid_data: Vec<u8>, eku_oid: &[u32], serial: i64| -> PkinitIdentity {
                let (nb, na) = test_validity().expect("validity window");
                let ee_key = BackendPrivateKey::generate_ec("P-256").unwrap();
                let pkcs8 = ee_key.to_der().unwrap();
                let spki = ee_key.public_key_spki_der().unwrap();
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
                    .serial_number(Integer::from_i64(serial))
                    .not_valid_before(Time::UtcTime(nb))
                    .not_valid_after(Time::UtcTime(na))
                    .add_extension_oid(synta_certificate::oids::SUBJECT_ALT_NAME, false, &san_der)
                    .add_extension_oid(synta_certificate::oids::EXTENDED_KEY_USAGE, false, &eku_der)
                    .add_extension_oid(synta_certificate::oids::KEY_USAGE, true, &ku_der)
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
                    signing_key: Some(
                        synta_certificate::crypto::BackendPrivateKey::from_pkcs8_der_unchecked(
                            pkcs8,
                        ),
                    ),
                    chain: vec![ca_cert_der.clone()],
                }
            };

        let client_san = synta_krb5::principal::encode_krb5_san("testuser", "EXAMPLE.COM").unwrap();
        let client_id = make_identity(
            "Test Client",
            client_san,
            constants::ID_PKINIT_KPCLIENT_AUTH,
            2,
        );

        let kdc_san =
            synta_krb5::principal::encode_krb5_san("krbtgt/EXAMPLE.COM", "EXAMPLE.COM").unwrap();
        let kdc_id = make_identity("Test KDC", kdc_san, constants::ID_PKINIT_KPKDC, 3);

        let mut trust_store = TrustStore::new();
        trust_store.add_anchor(ca_cert_der);

        (client_id, kdc_id, trust_store)
    }

    #[test]
    fn kem_client_public_value_must_not_carry_parameters() {
        use crate::error::KemErrorClass;

        let spki_der = crate::crypto::kem::KemKeyPair::generate(KemAlgorithm::MlKem768)
            .unwrap()
            .public_key_spki_der()
            .unwrap();
        assert_eq!(
            detect_spki_algorithm(&spki_der).unwrap(),
            Some(KemAlgorithm::MlKem768)
        );

        let mut spki: synta_krb5::kerberos_v5_pkinit_agility::SubjectPublicKeyInfo<'_> =
            synta::Decoder::new(&spki_der, synta::Encoding::Der)
                .decode()
                .unwrap();
        spki.algorithm.parameters = Some(synta::Element::Null(synta::Null));
        let with_params = spki.to_der().unwrap();
        let err = detect_spki_algorithm(&with_params).unwrap_err();
        assert_eq!(
            err.kem_error_class(),
            KemErrorClass::EphemeralKeyParamsNotAccepted,
            "{err}"
        );
    }

    #[test]
    fn kdc_state_construction() {
        let (_, kdc_id, trust_store) = generate_test_pki();
        let state = PkinitKdcState::new(kdc_id, trust_store, PkinitKdcConfig::default()).unwrap();
        assert!(state.config.require_eku);
    }

    #[test]
    fn full_pkinit_dh_exchange() {
        let (client_id, kdc_id, trust_store) = generate_test_pki();
        let o2k = MockO2K;

        let client_config = PkinitClientConfig {
            dh_group: DhGroup::EcP256,
            ..Default::default()
        };
        let mut client = PkinitClientState::new(client_id, trust_store.clone(), client_config);
        client.set_kdc_identity("krbtgt/EXAMPLE.COM@EXAMPLE.COM".to_string(), None);

        let server = PkinitKdcState::new(kdc_id, trust_store, PkinitKdcConfig::default()).unwrap();

        let req_body_der = b"mock-req-body";
        let ctime = 1719600000i64;
        let nonce = next_nonce();
        let pa_req = client.build_as_req(nonce, ctime, 0, req_body_der).unwrap();

        let verified = server
            .verify_as_req(&pa_req, Some(req_body_der), 300, ctime)
            .unwrap();
        assert!(!verified.is_anonymous);

        let as_req_der = b"mock-full-as-req";
        let client_name = "testuser@EXAMPLE.COM";
        let server_name = "krbtgt/EXAMPLE.COM@EXAMPLE.COM";
        let (pa_rep, server_key) = server
            .build_as_rep(
                &verified,
                &BuildAsRepParams {
                    nonce,
                    enctype: 18,
                    as_req_der,
                    client_name,
                    server_name,
                },
                &o2k,
            )
            .unwrap();

        let client_key = client
            .process_as_rep(
                &pa_rep,
                &crate::client::AsRepParams {
                    nonce,
                    enctype: 18,
                    as_req_der,
                    pa_rep_raw: &pa_rep,
                    client_name,
                    server_name,
                },
                &o2k,
            )
            .unwrap();

        assert_eq!(client_key.enctype, server_key.enctype);
        assert_eq!(client_key.key_data.as_ref(), server_key.key_data.as_ref());
    }

    /// Run a KEM exchange, but have the KDC sign a KDCKEMInfo whose
    /// kdfAlgorithm was replaced by `edit`, and return the client's verdict.
    fn kem_exchange_with_signed_kdf(
        edit: impl FnOnce(&mut synta_certificate::AlgorithmIdentifier<'static>),
    ) -> Result<crate::crypto::kdf::DerivedKey, PkinitError> {
        use crate::kem_types::{
            KdcKemInfo, KemRepInfo, decode_kem_rep_content, encode_kem_rep_wrapper,
        };

        let (client_id, kdc_id, trust_store) = generate_test_pki();
        let o2k = MockO2K;
        let mut client = PkinitClientState::new(
            client_id,
            trust_store.clone(),
            PkinitClientConfig {
                kem_algorithm: Some(KemAlgorithm::MlKem768),
                ..Default::default()
            },
        );
        client.set_kdc_identity("krbtgt/EXAMPLE.COM@EXAMPLE.COM".to_string(), None);
        let server = PkinitKdcState::new(kdc_id, trust_store, PkinitKdcConfig::default()).unwrap();

        let req_body_der = b"mock-req-body";
        let ctime = 1719600000i64;
        let nonce = next_nonce();
        let pa_req = client.build_as_req(nonce, ctime, 0, req_body_der).unwrap();
        let verified = server
            .verify_as_req(&pa_req, Some(req_body_der), 300, ctime)
            .unwrap();
        let as_req_der = b"mock-full-as-req";
        let client_name = "testuser@EXAMPLE.COM";
        let server_name = "krbtgt/EXAMPLE.COM@EXAMPLE.COM";
        let (pa_rep, _) = server
            .build_as_rep(
                &verified,
                &BuildAsRepParams {
                    nonce,
                    enctype: 18,
                    as_req_der,
                    client_name,
                    server_name,
                },
                &o2k,
            )
            .unwrap();

        // Re-sign an edited KDCKEMInfo with the genuine KDC key, so the reply
        // passes every check except the one under test.
        let kem_rep_info = KemRepInfo::from_der(&decode_kem_rep_content(&pa_rep).unwrap()).unwrap();
        let signed = cms::verify_signed_data(kem_rep_info.kem_signed_data.as_bytes()).unwrap();
        let info = KdcKemInfo::from_der(&signed.content).unwrap();
        let mut kdf_algorithm = synta_certificate::AlgorithmIdentifier {
            algorithm: info.kdf_algorithm.algorithm.clone(),
            parameters: None,
        };
        edit(&mut kdf_algorithm);
        let edited = KdcKemInfo {
            kdf_algorithm,
            ..info
        };
        let chain: Vec<&[u8]> = server.identity.chain.iter().map(|c| c.as_slice()).collect();
        let resigned = cms::create_signed_data(
            &edited.to_der().unwrap(),
            constants::ID_PKINIT_KEM_KEY_DATA,
            server.identity.signing_key.as_ref().unwrap(),
            &server.identity.cert_der,
            &chain,
            "sha256",
        )
        .unwrap();
        let pa_rep = encode_kem_rep_wrapper(&KemRepInfo {
            kem_signed_data: synta::OctetString::new(resigned),
        })
        .unwrap();

        client.process_as_rep(
            &pa_rep,
            &crate::client::AsRepParams {
                nonce,
                enctype: 18,
                as_req_der,
                pa_rep_raw: &pa_rep,
                client_name,
                server_name,
            },
            &o2k,
        )
    }

    #[test]
    fn client_accepts_signed_hkdf_sha512() {
        kem_exchange_with_signed_kdf(|_| {}).expect("unmodified KDF must be accepted");
    }

    #[test]
    fn client_rejects_signed_kdf_it_did_not_offer() {
        let err = kem_exchange_with_signed_kdf(|kdf| {
            kdf.algorithm =
                synta::ObjectIdentifier::new(constants::ID_PKINIT_KDF_AH_SHA512).unwrap();
        })
        .err()
        .expect("a KDF the client did not offer must be rejected");
        assert!(matches!(err, PkinitError::KdfNotOffered(_)), "{err}");
    }

    #[test]
    fn client_rejects_signed_kdf_with_parameters() {
        let err = kem_exchange_with_signed_kdf(|kdf| {
            kdf.parameters = Some(synta::Element::Null(synta::Null));
        })
        .err()
        .expect("kdfAlgorithm parameters must be absent");
        assert!(matches!(err, PkinitError::KdfNotOffered(_)), "{err}");
    }

    #[test]
    fn tampered_signature_is_invalid_sig_not_anonymous() {
        use crate::error::KemErrorClass;

        let (client_id, kdc_id, trust_store) = generate_test_pki();
        let mut client = PkinitClientState::new(
            client_id,
            trust_store.clone(),
            PkinitClientConfig {
                dh_group: DhGroup::EcP256,
                ..Default::default()
            },
        );
        client.set_kdc_identity("krbtgt/EXAMPLE.COM@EXAMPLE.COM".to_string(), None);
        let server = PkinitKdcState::new(kdc_id, trust_store, PkinitKdcConfig::default()).unwrap();

        let req_body_der = b"mock-req-body";
        let ctime = 1719600000i64;
        let mut pa_req = client
            .build_as_req(next_nonce(), ctime, 0, req_body_der)
            .unwrap();
        // PA-PK-AS-REQ carries only signedAuthPack, whose SignerInfo (and
        // so the signature value) comes last: corrupt its final byte.
        *pa_req.last_mut().unwrap() ^= 0x01;

        let err = server
            .verify_as_req(&pa_req, Some(req_body_der), 300, ctime)
            .expect_err("a corrupted signature must not verify, nor pass as anonymous");
        assert_eq!(
            err.kem_error_class(),
            KemErrorClass::InvalidSignature,
            "{err}"
        );
    }

    #[test]
    fn require_kem_rejects_classic_dh_request() {
        use crate::error::KemErrorClass;

        let (client_id, kdc_id, trust_store) = generate_test_pki();
        let client_config = PkinitClientConfig {
            dh_group: DhGroup::EcP256,
            ..Default::default()
        };
        let mut client = PkinitClientState::new(client_id, trust_store.clone(), client_config);
        client.set_kdc_identity("krbtgt/EXAMPLE.COM@EXAMPLE.COM".to_string(), None);

        let server = PkinitKdcState::new(
            kdc_id,
            trust_store,
            PkinitKdcConfig {
                require_kem: true,
                ..Default::default()
            },
        )
        .unwrap();

        let req_body_der = b"mock-req-body";
        let ctime = 1719600000i64;
        let pa_req = client
            .build_as_req(next_nonce(), ctime, 0, req_body_der)
            .unwrap();
        let err = server
            .verify_as_req(&pa_req, Some(req_body_der), 300, ctime)
            .unwrap_err();
        assert!(matches!(err, PkinitError::DhParamsRejected(_)));
        assert_eq!(
            err.kem_error_class(),
            KemErrorClass::EphemeralKeyParamsNotAccepted
        );
    }

    #[test]
    fn require_kem_advertises_only_kem_algorithms() {
        let (_, kdc_id, trust_store) = generate_test_pki();
        let server = PkinitKdcState::new(
            kdc_id,
            trust_store,
            PkinitKdcConfig {
                require_kem: true,
                ..Default::default()
            },
        )
        .unwrap();

        // No KEM floor configured: every pure ML-KEM parameter set is
        // accepted and advertised, and no DH/ECDH group is offered.
        assert_eq!(
            server.config.supported_kem_algorithms,
            vec![
                KemAlgorithm::MlKem512,
                KemAlgorithm::MlKem768,
                KemAlgorithm::MlKem1024
            ]
        );
        let alg_ids = acceptable_key_establishment_alg_ids(&server.config).unwrap();
        assert_eq!(alg_ids.len(), 3);
        for id in &alg_ids {
            assert!(
                [
                    KemAlgorithm::MlKem512,
                    KemAlgorithm::MlKem768,
                    KemAlgorithm::MlKem1024
                ]
                .iter()
                .any(|alg| id.algorithm.components() == alg.oid()),
                "unexpected algorithm offered: {:?}",
                id.algorithm
            );
        }
    }

    #[test]
    fn hint_advertises_every_accepted_algorithm_in_preference_order() {
        use crate::kem_types::{offered_algorithm, parse_pkinit_hint};

        let (_, kdc_id, trust_store) = generate_test_pki();
        let server = PkinitKdcState::new(
            kdc_id,
            trust_store,
            PkinitKdcConfig {
                supported_kem_algorithms: KemAlgorithm::MlKem512.algorithms_at_or_above(),
                supported_composite_kem_algorithms: vec![KemAlgorithm::MlKem768X25519],
                ..Default::default()
            },
        )
        .unwrap();

        let hint = parse_pkinit_hint(&server.build_supported_algorithms_hint().unwrap()).unwrap();
        // Same list, same order, as the reactive TD-EPHEMERAL-KEY-PARAMETERS.
        let td: Vec<_> = acceptable_key_establishment_alg_ids(&server.config)
            .unwrap()
            .iter()
            .map(|a| offered_algorithm(a).unwrap())
            .collect();
        assert_eq!(hint, td);

        // Pure ML-KEM strongest first, then the composite, then the MODP
        // groups at or above the default 2048-bit floor (with their domain
        // parameters), strongest first.
        let kems: Vec<&[u32]> = hint[..4].iter().map(|(oid, _)| oid.as_slice()).collect();
        assert_eq!(
            kems,
            [
                KemAlgorithm::MlKem1024.oid(),
                KemAlgorithm::MlKem768.oid(),
                KemAlgorithm::MlKem512.oid(),
                KemAlgorithm::MlKem768X25519.oid(),
            ]
        );
        let groups = &hint[4..];
        assert_eq!(groups.len(), 2, "DH groups accepted must be advertised");
        assert!(groups.iter().all(|(_, params)| params.is_some()));
        assert!(groups[0].1.as_ref().unwrap().len() > groups[1].1.as_ref().unwrap().len());
    }

    #[test]
    fn require_kem_full_exchange_with_classical_certificates() {
        // The point of require_kem: a post-quantum key exchange regardless of
        // the certificate algorithm (here ECDSA P-256 on both sides).
        let (client_id, kdc_id, trust_store) = generate_test_pki();
        let o2k = MockO2K;

        let mut client = PkinitClientState::new(
            client_id,
            trust_store.clone(),
            PkinitClientConfig {
                require_kem: true,
                ..Default::default()
            },
        );
        client.set_kdc_identity("krbtgt/EXAMPLE.COM@EXAMPLE.COM".to_string(), None);
        let server = PkinitKdcState::new(
            kdc_id,
            trust_store,
            PkinitKdcConfig {
                require_kem: true,
                ..Default::default()
            },
        )
        .unwrap();

        let req_body_der = b"mock-req-body";
        let ctime = 1719600000i64;
        let nonce = next_nonce();
        let pa_req = client.build_as_req(nonce, ctime, 0, req_body_der).unwrap();
        let verified = server
            .verify_as_req(&pa_req, Some(req_body_der), 300, ctime)
            .unwrap();
        assert_eq!(
            verified.key_exchange,
            KeyExchangeType::Kem(KemAlgorithm::MlKem768)
        );

        let as_req_der = b"mock-full-as-req";
        let client_name = "testuser@EXAMPLE.COM";
        let server_name = "krbtgt/EXAMPLE.COM@EXAMPLE.COM";
        let (pa_rep, server_key) = server
            .build_as_rep(
                &verified,
                &BuildAsRepParams {
                    nonce,
                    enctype: 18,
                    as_req_der,
                    client_name,
                    server_name,
                },
                &o2k,
            )
            .unwrap();
        let client_key = client
            .process_as_rep(
                &pa_rep,
                &crate::client::AsRepParams {
                    nonce,
                    enctype: 18,
                    as_req_der,
                    pa_rep_raw: &pa_rep,
                    client_name,
                    server_name,
                },
                &o2k,
            )
            .unwrap();
        assert_eq!(client_key.key_data.as_ref(), server_key.key_data.as_ref());
    }

    #[test]
    fn build_kem_rep_rejects_unapproved_kdf() {
        use crate::crypto::kem::KemKeyPair;

        let (_, kdc_id, trust_store) = generate_test_pki();
        let o2k = MockO2K;

        let server = PkinitKdcState::new(kdc_id, trust_store, PkinitKdcConfig::default()).unwrap();

        let kem_kp = KemKeyPair::generate(constants::KemAlgorithm::MlKem768).unwrap();
        let client_dh_public = kem_kp.public_key_spki_der().unwrap();

        // {{sec-kdf-oids}}: only id-alg-hkdf-with-sha512 is approved for the
        // KEM path; a client offering only an unapproved KDF must be
        // rejected with KDC_ERR_NO_ACCEPTABLE_KDF, not silently defaulted.
        let nonce = next_nonce();
        let verified = VerifiedRequest {
            client_cert_der: vec![],
            client_dh_public,
            nonce,
            supported_kdfs: vec![vec![9, 9, 9]],
            client_dh_nonce: None,
            is_anonymous: false,
            key_exchange: KeyExchangeType::Kem(constants::KemAlgorithm::MlKem768),
        };

        // `DerivedKey` deliberately doesn't implement `Debug` (it holds key
        // material via `SecretBuf`), so `unwrap_err()` would fail to compile
        // here; map the Ok side away first.
        let err = server
            .build_as_rep(
                &verified,
                &BuildAsRepParams {
                    nonce,
                    enctype: 18,
                    as_req_der: b"mock-as-req",
                    client_name: "testuser@EXAMPLE.COM",
                    server_name: "krbtgt/EXAMPLE.COM@EXAMPLE.COM",
                },
                &o2k,
            )
            .map(|_| ())
            .unwrap_err();

        assert!(matches!(err, PkinitError::NoAcceptableKdf));
        assert_eq!(
            err.kem_error_class(),
            crate::error::KemErrorClass::NoAcceptableKdf
        );
    }
}
