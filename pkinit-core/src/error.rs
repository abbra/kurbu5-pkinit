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

    #[error("freshness token required but not provided")]
    FreshnessRequired,

    #[error("freshness token verification failed")]
    FreshnessInvalid,

    #[error("anonymous PKINIT not permitted")]
    AnonymousNotPermitted,

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

    #[error("downgrade rejected: {0}")]
    DowngradeRejected(String),

    #[error("unsupported operation: {0}")]
    Unsupported(String),
}
