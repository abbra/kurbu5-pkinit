use crate::error::PkinitError;
use synta_certificate::crypto::DataHasher;
use synta_certificate::default_data_hasher;

pub struct Checksums {
    pub sha1: Vec<u8>,
    pub sha256: Vec<u8>,
}

pub fn generate_checksums(req_body_der: &[u8]) -> Result<Checksums, PkinitError> {
    let hasher = default_data_hasher();
    let sha1 = hasher
        .hash_data("sha1", req_body_der)
        .map_err(|e| PkinitError::Ossl(format!("SHA-1 hash failed: {e}")))?;
    let sha256 = hasher
        .hash_data("sha256", req_body_der)
        .map_err(|e| PkinitError::Ossl(format!("SHA-256 hash failed: {e}")))?;
    Ok(Checksums { sha1, sha256 })
}

fn hash_for_algorithm(algorithm: &str, data: &[u8]) -> Result<Vec<u8>, PkinitError> {
    let hasher = default_data_hasher();
    hasher
        .hash_data(algorithm, data)
        .map_err(|e| PkinitError::Ossl(format!("{algorithm} hash failed: {e}")))
}

fn oid_to_algorithm(oid: &[u32]) -> Option<&'static str> {
    synta_certificate::oids::digest_oid_to_name(oid)
}

pub fn verify_checksums(
    req_body_der: &[u8],
    pa_checksum: &[u8],
    pa_checksum2: Option<(&[u8], &[u32])>,
) -> Result<(), PkinitError> {
    let computed = generate_checksums(req_body_der)?;

    match pa_checksum.len() {
        32 => {
            if !native_ossl::util::ct_eq(&computed.sha256, pa_checksum) {
                return Err(PkinitError::ChecksumFailed);
            }
        }
        20 => {
            if !native_ossl::util::ct_eq(&computed.sha1, pa_checksum) {
                return Err(PkinitError::ChecksumFailed);
            }
        }
        _ => return Err(PkinitError::ChecksumFailed),
    }

    if let Some((checksum_bytes, algorithm_oid)) = pa_checksum2 {
        verify_checksum2(req_body_der, checksum_bytes, algorithm_oid)?;
    }

    Ok(())
}

pub fn verify_checksum2(
    req_body_der: &[u8],
    checksum_bytes: &[u8],
    algorithm_oid: &[u32],
) -> Result<(), PkinitError> {
    let alg = oid_to_algorithm(algorithm_oid).ok_or(PkinitError::ChecksumFailed)?;
    let expected = hash_for_algorithm(alg, req_body_der)?;
    if !native_ossl::util::ct_eq(&expected, checksum_bytes) {
        return Err(PkinitError::ChecksumFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_checksums_produces_sha1_and_sha256() {
        let input = b"test request body";
        let checksums = generate_checksums(input).unwrap();
        assert_eq!(checksums.sha1.len(), 20);
        assert_eq!(checksums.sha256.len(), 32);
    }

    #[test]
    fn verify_checksums_accepts_valid() {
        let input = b"test request body";
        let checksums = generate_checksums(input).unwrap();
        verify_checksums(
            input,
            &checksums.sha1,
            Some((&checksums.sha256, synta_certificate::oids::ID_SHA256)),
        )
        .unwrap();
    }

    #[test]
    fn verify_checksums_rejects_bad_sha1() {
        let input = b"test request body";
        let bad = vec![0u8; 20];
        let checksums = generate_checksums(input).unwrap();
        assert!(
            verify_checksums(
                input,
                &bad,
                Some((&checksums.sha256, synta_certificate::oids::ID_SHA256)),
            )
            .is_err()
        );
    }

    #[test]
    fn verify_checksums_rejects_bad_sha256() {
        let input = b"test request body";
        let checksums = generate_checksums(input).unwrap();
        let bad = vec![0u8; 32];
        assert!(
            verify_checksums(
                input,
                &checksums.sha1,
                Some((&bad, synta_certificate::oids::ID_SHA256)),
            )
            .is_err()
        );
    }

    #[test]
    fn verify_checksums_sha1_only_when_no_sha256() {
        let input = b"test request body";
        let checksums = generate_checksums(input).unwrap();
        verify_checksums(input, &checksums.sha1, None).unwrap();
    }

    #[test]
    fn verify_checksums_sha384() {
        let input = b"test request body";
        let checksums = generate_checksums(input).unwrap();
        let sha384 = hash_for_algorithm("sha384", input).unwrap();
        assert_eq!(sha384.len(), 48);
        verify_checksums(
            input,
            &checksums.sha1,
            Some((&sha384, synta_certificate::oids::ID_SHA384)),
        )
        .unwrap();
    }

    #[test]
    fn verify_checksums_sha512() {
        let input = b"test request body";
        let checksums = generate_checksums(input).unwrap();
        let sha512 = hash_for_algorithm("sha512", input).unwrap();
        assert_eq!(sha512.len(), 64);
        verify_checksums(
            input,
            &checksums.sha1,
            Some((&sha512, synta_certificate::oids::ID_SHA512)),
        )
        .unwrap();
    }

    #[test]
    fn verify_checksums_rejects_unknown_oid() {
        let input = b"test request body";
        let checksums = generate_checksums(input).unwrap();
        let unknown_oid: &[u32] = &[1, 2, 3, 4, 5];
        assert!(
            verify_checksums(
                input,
                &checksums.sha1,
                Some((&checksums.sha256, unknown_oid)),
            )
            .is_err()
        );
    }
}
