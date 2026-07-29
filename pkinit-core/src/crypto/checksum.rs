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

pub fn verify_checksums(
    req_body_der: &[u8],
    pa_checksum: &[u8],
    pa_checksum2: Option<&[u8]>,
) -> Result<(), PkinitError> {
    let computed = generate_checksums(req_body_der)?;

    match pa_checksum.len() {
        32 => {
            if computed.sha256 != pa_checksum {
                return Err(PkinitError::ChecksumFailed);
            }
        }
        20 => {
            if computed.sha1 != pa_checksum {
                return Err(PkinitError::ChecksumFailed);
            }
        }
        _ => return Err(PkinitError::ChecksumFailed),
    }

    if let Some(sha256) = pa_checksum2 {
        if computed.sha256 != sha256 {
            return Err(PkinitError::ChecksumFailed);
        }
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
        verify_checksums(input, &checksums.sha1, Some(&checksums.sha256)).unwrap();
    }

    #[test]
    fn verify_checksums_rejects_bad_sha1() {
        let input = b"test request body";
        let bad = vec![0u8; 20];
        let checksums = generate_checksums(input).unwrap();
        assert!(verify_checksums(input, &bad, Some(&checksums.sha256)).is_err());
    }

    #[test]
    fn verify_checksums_rejects_bad_sha256() {
        let input = b"test request body";
        let checksums = generate_checksums(input).unwrap();
        let bad = vec![0u8; 32];
        assert!(verify_checksums(input, &checksums.sha1, Some(&bad)).is_err());
    }

    #[test]
    fn verify_checksums_sha1_only_when_no_sha256() {
        let input = b"test request body";
        let checksums = generate_checksums(input).unwrap();
        verify_checksums(input, &checksums.sha1, None).unwrap();
    }
}
