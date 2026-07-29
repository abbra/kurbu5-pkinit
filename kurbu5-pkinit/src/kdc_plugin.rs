use kurbu5_rs::kdcpreauth::*;
use kurbu5_rs::{
    CertRef, CertauthDecision, CertauthModule, Krb5Error, KdcpreauthCallbacks,
    KdcpreauthModule, PluginContext, ReturnPadataRequest, VerifyResponse,
    PA_HARDWARE, PA_REPLACES_KEY, PA_SUFFICIENT, PA_TYPED_E_DATA,
};
use pkinit_core::certauth;
use pkinit_core::config::PkinitKdcConfig;
use pkinit_core::identity::{IdentitySource, PkinitIdentity, TrustStore};
use pkinit_core::server::{PkinitKdcState, VerifiedRequest};

use crate::o2k::Krb5OctetString2Key;
use crate::profile;

pub struct PkinitKdc {
    state: PkinitKdcState,
    config: PkinitKdcConfig,
}

struct PkinitModReq {
    verified: VerifiedRequest,
}

impl KdcpreauthModule for PkinitKdc {
    const NAME: &'static std::ffi::CStr = c"pkinit";

    fn pa_type_list() -> &'static [i32] {
        static LIST: [i32; 3] = [16, 147, 0];
        &LIST
    }

    fn init_module(ctx: &PluginContext<'_>, realmnames: &[&str]) -> Result<Self, Krb5Error> {
        let realm = realmnames.first().ok_or(Krb5Error::Custom(libc::EINVAL))?;
        let profile = kurbu5_rs::Profile::from_context(ctx)?;
        let config = profile::read_kdc_config(&profile, realm);

        let identity_str = config
            .identity
            .as_deref()
            .ok_or(Krb5Error::NoHandle)?;

        let source =
            IdentitySource::parse(identity_str).map_err(|_| Krb5Error::Custom(libc::EINVAL))?;
        let identity =
            PkinitIdentity::load(&source).map_err(|_| Krb5Error::Custom(libc::EINVAL))?;

        let mut trust_store = TrustStore::new();
        for anchor in &config.anchors {
            trust_store
                .load_from_path(anchor)
                .map_err(|_| Krb5Error::Custom(libc::EINVAL))?;
        }

        let state = PkinitKdcState::new(identity, trust_store, config.clone());
        Ok(PkinitKdc { state, config })
    }

    fn flags_for_type(_ctx: &PluginContext<'_>, _pa_type: i32) -> i32 {
        PA_SUFFICIENT | PA_REPLACES_KEY | PA_TYPED_E_DATA | PA_HARDWARE
    }

    fn get_edata(
        &self,
        _ctx: &PluginContext<'_>,
        _pa_type: i32,
        callbacks: &KdcpreauthCallbacks<'_>,
        respond: Box<dyn FnOnce(Result<Option<PaData>, Krb5Error>)>,
    ) {
        callbacks.send_freshness_token();
        respond(Ok(None));
    }

    fn verify(
        &self,
        _ctx: &PluginContext<'_>,
        pa_data: &PaData,
        callbacks: &KdcpreauthCallbacks<'_>,
        respond: Box<dyn FnOnce(VerifyResponse)>,
    ) {
        let pa_contents = &pa_data.contents;
        if pa_contents.is_empty() {
            respond(VerifyResponse::err(libc::EINVAL));
            return;
        }

        let max_skew = callbacks.max_time_skew();
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let req_body_der = pa_contents;

        let verified = match self.state.verify_as_req(
            pa_contents,
            req_body_der,
            max_skew,
            current_time,
            None,
        ) {
            Ok(v) => v,
            Err(e) => {
                let _ = &e;
                respond(VerifyResponse::err(libc::EINVAL));
                return;
            }
        };

        if !verified.is_anonymous {
            for indicator in &self.config.auth_indicators {
                let _ = callbacks.add_auth_indicator(indicator);
            }
        }

        let modreq = Box::new(PkinitModReq { verified });
        respond(VerifyResponse::ok_with_modreq(modreq));
    }

    fn return_padata(
        &self,
        ctx: &PluginContext<'_>,
        req: ReturnPadataRequest<'_>,
        callbacks: &KdcpreauthCallbacks<'_>,
    ) -> Result<Option<PaData>, Krb5Error> {
        let modreq = req
            .modreq
            .and_then(|m| m.downcast_ref::<PkinitModReq>())
            .ok_or(Krb5Error::Custom(libc::EINVAL))?;

        let nonce = modreq.verified.nonce;
        let enctype = callbacks
            .fast_armor()
            .map(|k| k.enctype)
            .unwrap_or(18);

        let o2k = Krb5OctetString2Key::new(ctx);
        let as_req_der = b"";

        let (pa_rep_der, derived) = self
            .state
            .build_as_rep(&modreq.verified, nonce, enctype, as_req_der, &o2k)
            .map_err(|_| Krb5Error::Custom(libc::EINVAL))?;

        let keyblock = kurbu5_sys::krb5_keyblock {
            magic: 0,
            enctype: derived.enctype,
            length: derived.key_data.len() as u32,
            contents: derived.key_data.as_ptr() as *mut u8,
        };
        callbacks.replace_reply_key(&keyblock, false)?;

        Ok(Some(PaData::new(17, pa_rep_der)))
    }
}

pub struct PkinitCertauth;

impl CertauthModule for PkinitCertauth {
    const NAME: &'static std::ffi::CStr = c"pkinit";

    fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
        Ok(PkinitCertauth)
    }

    fn authorize(
        &self,
        ctx: &PluginContext<'_>,
        cert: CertRef<'_>,
        princ: &kurbu5_sys::krb5_principal_data,
    ) -> Result<CertauthDecision, Krb5Error> {
        let princ_str = ctx.unparse_principal(princ)?;
        let parts: Vec<&str> = princ_str.splitn(2, '@').collect();
        if parts.len() != 2 {
            return Ok(CertauthDecision::NoOpinion);
        }
        let (principal, realm) = (parts[0], parts[1]);

        let result = certauth::verify_client_san(cert.as_der(), principal, realm, true)
            .map_err(|_| Krb5Error::Custom(libc::EINVAL))?;

        match result {
            pkinit_core::certauth::CertauthResult::Authorized => {
                Ok(CertauthDecision::Authorized)
            }
            pkinit_core::certauth::CertauthResult::AuthorizedHwauth => {
                Ok(CertauthDecision::AuthorizedHwauth)
            }
            pkinit_core::certauth::CertauthResult::NoOpinion => {
                Ok(CertauthDecision::NoOpinion)
            }
            pkinit_core::certauth::CertauthResult::Rejected(_) => {
                Ok(CertauthDecision::NoOpinion)
            }
        }
    }
}
