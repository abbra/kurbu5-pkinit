use thiserror::Error;

#[derive(Debug, Error)]
pub enum PkinitError {
    #[error("CMS signature creation failed: {0}")]
    CmsSignFailed(String),

    #[error("CMS signature verification failed: {0}")]
    CmsVerifyFailed(String),

    #[error("CMS content type mismatch: expected {expected}, got {actual}")]
    CmsContentTypeMismatch { expected: String, actual: String },

    #[error("DH parameters rejected: {0}")]
    DhParamsRejected(String),

    #[error("DH key agreement failed: {0}")]
    DhAgreementFailed(String),

    #[error("KDF derivation failed: {0}")]
    KdfFailed(String),

    #[error("certificate SAN mismatch: {0}")]
    SanMismatch(String),

    #[error("certificate EKU mismatch: {0}")]
    EkuMismatch(String),

    #[error("certificate matching rule rejected: {0}")]
    CertMatchRejected(String),

    #[error("identity load failed: {0}")]
    IdentityLoadFailed(String),

    #[error("certificate chain validation failed: {0}")]
    ChainValidationFailed(String),

    #[error("clock skew too large: client={client_time}, allowed_skew={max_skew}s")]
    ClockSkew { client_time: i64, max_skew: i64 },

    #[error("checksum verification failed")]
    ChecksumFailed,

    #[error("nonce mismatch: expected {expected}, got {actual}")]
    NonceMismatch { expected: i32, actual: i32 },

    #[error("no supported KDF algorithm")]
    NoSupportedKdf,

    #[error("ASN.1 encoding/decoding error: {0}")]
    Asn1(String),

    #[error("OpenSSL error: {0}")]
    Ossl(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("KEM encapsulation failed: {0}")]
    KemEncapFailed(String),

    #[error("KEM decapsulation failed: {0}")]
    KemDecapFailed(String),

    #[error("KEM algorithm mismatch: expected {expected}, got {actual}")]
    KemAlgorithmMismatch { expected: String, actual: String },

    #[error("KEM ciphertext length invalid: expected {expected}, got {actual}")]
    KemCiphertextLengthInvalid { expected: usize, actual: usize },

    #[error("KEM algorithm not supported: {0}")]
    KemAlgorithmNotSupported(String),

    #[error("no acceptable KDF for the negotiated path")]
    NoAcceptableKdf,

    #[error("clientDHNonce must be absent when clientPublicValue carries a KEM algorithm")]
    KemNonceNotAllowed,

    #[error("downgrade rejected: {0}")]
    DowngradeRejected(String),

    #[error("unsupported operation: {0}")]
    Unsupported(String),
}

/// Wrap a `synta` encode/decode failure as [`PkinitError::Asn1`] with a
/// short static context, e.g. `.map_err(asn1_err("KEM OID"))?`, instead of
/// restating `.map_err(|e| PkinitError::Asn1(format!("KEM OID: {e}")))` at
/// every ASN.1 call site.
pub(crate) fn asn1_err(context: &'static str) -> impl FnOnce(synta::Error) -> PkinitError {
    move |e| PkinitError::Asn1(format!("{context}: {e}"))
}

/// Classification of a [`PkinitError`] into the specific KRB-ERROR the draft
/// mandates, so `kurbu5-pkinit`'s krb5 plugin layer can map it to the actual
/// `KRB5KDC_ERR_*` constant and attach `TD-EPHEMERAL-KEY-PARAMETERS-DATA`
/// without `pkinit-core` itself depending on krb5 FFI bindings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemErrorClass {
    /// draft {{sec-ephemeral-key-errors}}: `KDC_ERR_EPHEMERAL_KEY_PARAMS_NOT_ACCEPTED`
    /// (error 65), with `TD-EPHEMERAL-KEY-PARAMETERS-DATA` listing acceptable
    /// algorithms.
    EphemeralKeyParamsNotAccepted,
    /// draft {{sec-kdf-oids}} / {{sec-kdc-response}} step 3:
    /// `KDC_ERR_NO_ACCEPTABLE_KDF` (error 100).
    NoAcceptableKdf,
    /// draft {{sec-mode-selection}}: `clientDHNonce` present alongside a KEM
    /// OID in `clientPublicValue` — `KDC_ERR_PREAUTH_FAILED`.
    PreauthFailed,
    /// No specific error code is mandated by the draft; the plugin layer
    /// should fall back to a generic preauth failure.
    Other,
}

impl PkinitError {
    /// Classify this error for KRB-ERROR code / typed-data purposes.  See
    /// [`KemErrorClass`].
    pub fn kem_error_class(&self) -> KemErrorClass {
        match self {
            PkinitError::KemAlgorithmNotSupported(_) | PkinitError::DhParamsRejected(_) => {
                KemErrorClass::EphemeralKeyParamsNotAccepted
            }
            PkinitError::NoAcceptableKdf | PkinitError::NoSupportedKdf => {
                KemErrorClass::NoAcceptableKdf
            }
            PkinitError::KemNonceNotAllowed => KemErrorClass::PreauthFailed,
            _ => KemErrorClass::Other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_algorithm_not_supported_maps_to_ephemeral_key_params_not_accepted() {
        assert_eq!(
            PkinitError::KemAlgorithmNotSupported("ML-KEM-768".into()).kem_error_class(),
            KemErrorClass::EphemeralKeyParamsNotAccepted
        );
    }

    #[test]
    fn dh_params_rejected_maps_to_ephemeral_key_params_not_accepted() {
        assert_eq!(
            PkinitError::DhParamsRejected("weak group".into()).kem_error_class(),
            KemErrorClass::EphemeralKeyParamsNotAccepted
        );
    }

    #[test]
    fn no_acceptable_kdf_maps_to_no_acceptable_kdf() {
        assert_eq!(
            PkinitError::NoAcceptableKdf.kem_error_class(),
            KemErrorClass::NoAcceptableKdf
        );
        assert_eq!(
            PkinitError::NoSupportedKdf.kem_error_class(),
            KemErrorClass::NoAcceptableKdf
        );
    }

    #[test]
    fn kem_nonce_not_allowed_maps_to_preauth_failed() {
        assert_eq!(
            PkinitError::KemNonceNotAllowed.kem_error_class(),
            KemErrorClass::PreauthFailed
        );
    }

    #[test]
    fn unrelated_errors_map_to_other() {
        assert_eq!(
            PkinitError::ChecksumFailed.kem_error_class(),
            KemErrorClass::Other
        );
    }
}
