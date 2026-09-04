//! Varlink-backed implementation of `KdcCaTrustBroker`. Runs a single blocking
//! request/response against the broker's Unix socket using `smol::block_on`,
//! bridging the async zlink client into the synchronous preauth `process()`.

use std::path::PathBuf;
use std::time::Duration;

use base64::Engine;
use pkinit_core::error::PkinitError;
use pkinit_core::trust_broker::{KdcCaTrustBroker, KdcTrustDecision, KdcTrustRequest};
use pkinit_trust_proto::{Decision, KdcTrustProxy};

pub struct VarlinkTrustBroker {
    socket_path: PathBuf,
    timeout: Duration,
}

impl VarlinkTrustBroker {
    pub fn new(socket_path: PathBuf, timeout: Duration) -> Self {
        Self {
            socket_path,
            timeout,
        }
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

impl KdcCaTrustBroker for VarlinkTrustBroker {
    fn request_trust(&self, req: &KdcTrustRequest<'_>) -> Result<KdcTrustDecision, PkinitError> {
        let signer_b64 = b64(req.signer_cert_der);
        let presented_b64: Vec<String> = req.presented_certs_der.iter().map(|d| b64(d)).collect();

        let reply = smol::block_on(async {
            let call = async {
                let mut conn = zlink_smol::unix::connect(&self.socket_path)
                    .await
                    .map_err(|e| PkinitError::Config(format!("trust broker connect: {e}")))?;
                conn.request_trust(
                    req.realm,
                    req.kdc_principal,
                    &signer_b64,
                    presented_b64.clone(),
                    req.interactive,
                )
                .await
                .map_err(|e| PkinitError::Config(format!("trust broker call: {e}")))?
                .map_err(|e| PkinitError::Config(format!("trust broker error: {e:?}")))
            };
            let timeout = async {
                smol::Timer::after(self.timeout).await;
                Err(PkinitError::Config("trust broker timeout".into()))
            };
            smol::future::or(call, timeout).await
        })?;

        Ok(match reply.decision {
            Decision::Trusted => {
                let mut anchors = Vec::with_capacity(reply.anchors.len());
                for a in &reply.anchors {
                    let der = base64::engine::general_purpose::STANDARD
                        .decode(a)
                        .map_err(|e| {
                            PkinitError::Config(format!("trust broker anchor b64: {e}"))
                        })?;
                    anchors.push(der);
                }
                KdcTrustDecision::Trusted { anchors }
            }
            Decision::Denied => {
                KdcTrustDecision::Denied(reply.reason.unwrap_or_else(|| "denied".into()))
            }
            Decision::Unknown => KdcTrustDecision::Unknown,
        })
    }
}
