use std::path::PathBuf;

use crate::error::PkinitError;

pub mod loader;
pub mod matching;
pub mod store;

pub use store::TrustStore;

pub struct PkinitIdentity {
    pub cert_der: Vec<u8>,
    pub key_pkcs8_der: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub enum IdentitySource {
    File {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
    Dir {
        dir_path: PathBuf,
    },
    Pkcs12 {
        path: PathBuf,
    },
    Pkcs11Uri {
        uri: String,
    },
    Env {
        cert_var: String,
        key_var: String,
    },
}

impl IdentitySource {
    pub fn parse(uri: &str) -> Result<Self, PkinitError> {
        let (scheme, rest) = uri
            .split_once(':')
            .ok_or_else(|| PkinitError::Config(format!("identity URI missing scheme: {uri}")))?;

        match scheme {
            "FILE" => {
                let (cert, key) = rest.split_once(',').ok_or_else(|| {
                    PkinitError::Config(format!("FILE identity requires cert,key paths: {rest}"))
                })?;
                Ok(IdentitySource::File {
                    cert_path: PathBuf::from(cert),
                    key_path: PathBuf::from(key),
                })
            }
            "DIR" => Ok(IdentitySource::Dir {
                dir_path: PathBuf::from(rest),
            }),
            "PKCS12" => Ok(IdentitySource::Pkcs12 {
                path: PathBuf::from(rest),
            }),
            "PKCS11" => Ok(IdentitySource::Pkcs11Uri {
                uri: rest.to_string(),
            }),
            "ENV" => {
                let (cert_var, key_var) = rest.split_once(',').ok_or_else(|| {
                    PkinitError::Config(format!("ENV identity requires cert_var,key_var: {rest}"))
                })?;
                Ok(IdentitySource::Env {
                    cert_var: cert_var.to_string(),
                    key_var: key_var.to_string(),
                })
            }
            _ => Err(PkinitError::Config(format!(
                "unknown identity scheme: {scheme}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_file_identity() {
        let source = IdentitySource::parse("FILE:/path/cert.pem,/path/key.pem").unwrap();
        match source {
            IdentitySource::File {
                cert_path,
                key_path,
            } => {
                assert_eq!(cert_path.to_str().unwrap(), "/path/cert.pem");
                assert_eq!(key_path.to_str().unwrap(), "/path/key.pem");
            }
            _ => panic!("expected File variant"),
        }
    }

    #[test]
    fn parse_pkcs12_identity() {
        let source = IdentitySource::parse("PKCS12:/path/identity.p12").unwrap();
        match source {
            IdentitySource::Pkcs12 { path } => {
                assert_eq!(path.to_str().unwrap(), "/path/identity.p12");
            }
            _ => panic!("expected Pkcs12 variant"),
        }
    }

    #[test]
    fn parse_pkcs11_identity() {
        let source = IdentitySource::parse("PKCS11:pkcs11:token=MyToken").unwrap();
        match source {
            IdentitySource::Pkcs11Uri { uri } => {
                assert_eq!(uri, "pkcs11:token=MyToken");
            }
            _ => panic!("expected Pkcs11Uri variant"),
        }
    }

    #[test]
    fn parse_dir_identity() {
        let source = IdentitySource::parse("DIR:/path/to/certs").unwrap();
        match source {
            IdentitySource::Dir { dir_path } => {
                assert_eq!(dir_path.to_str().unwrap(), "/path/to/certs");
            }
            _ => panic!("expected Dir variant"),
        }
    }

    #[test]
    fn parse_env_identity() {
        let source = IdentitySource::parse("ENV:MY_CERT,MY_KEY").unwrap();
        match source {
            IdentitySource::Env { cert_var, key_var } => {
                assert_eq!(cert_var, "MY_CERT");
                assert_eq!(key_var, "MY_KEY");
            }
            _ => panic!("expected Env variant"),
        }
    }

    #[test]
    fn parse_unknown_scheme_fails() {
        assert!(IdentitySource::parse("UNKNOWN:foo").is_err());
    }

    #[test]
    fn parse_missing_scheme_fails() {
        assert!(IdentitySource::parse("no-colon-here").is_err());
    }

    #[test]
    fn parse_file_missing_key_fails() {
        assert!(IdentitySource::parse("FILE:/path/cert.pem").is_err());
    }

    #[test]
    fn parse_env_missing_key_var_fails() {
        assert!(IdentitySource::parse("ENV:MY_CERT").is_err());
    }
}
