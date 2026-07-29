use synta::OctetString;

use kurbu5_rs::kdcpreauth::*;
use kurbu5_rs::{
    CertRef, CertauthDecision, CertauthModule, KdcpreauthCallbacks, KdcpreauthModule, Krb5Error,
    PA_HARDWARE, PA_REPLACES_KEY, PA_SUFFICIENT, PA_TYPED_E_DATA, PluginContext,
    ReturnPadataRequest, VerifyResponse,
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

        let identity_str = config.identity.as_deref().ok_or(Krb5Error::NoHandle)?;

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

    fn flags_for_type(_ctx: &PluginContext<'_>, pa_type: i32) -> i32 {
        if pa_type == 147 {
            0
        } else {
            PA_SUFFICIENT | PA_REPLACES_KEY | PA_TYPED_E_DATA | PA_HARDWARE
        }
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

        let verified =
            match self
                .state
                .verify_as_req(pa_contents, None, max_skew, current_time, None)
            {
                Ok(v) => v,
                Err(_) => {
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
        let pa_type = req.padata.map(|p| p.pa_type).unwrap_or(0);
        match pa_type {
            16 => self.return_pkinit_dh(ctx, &req, callbacks),
            147 => Self::return_pkinit_kx(ctx, &req, callbacks),
            _ => Ok(None),
        }
    }
}

impl PkinitKdc {
    fn return_pkinit_dh(
        &self,
        ctx: &PluginContext<'_>,
        req: &ReturnPadataRequest<'_>,
        callbacks: &KdcpreauthCallbacks<'_>,
    ) -> Result<Option<PaData>, Krb5Error> {
        let modreq = req
            .modreq
            .and_then(|m| m.downcast_ref::<PkinitModReq>())
            .ok_or(Krb5Error::Custom(libc::EINVAL))?;

        let nonce = modreq.verified.nonce;
        let enctype = callbacks.fast_armor().map(|k| k.enctype).unwrap_or(18);

        let o2k = Krb5OctetString2Key::new(ctx);

        let client_name = callbacks
            .client_name_string(false)
            .ok_or(Krb5Error::Custom(libc::EINVAL))?;
        let server_name = unsafe {
            if req.request.is_null() {
                return Err(Krb5Error::Custom(libc::EINVAL));
            }
            let request = &*req.request;
            if request.server.is_null() {
                return Err(Krb5Error::Custom(libc::EINVAL));
            }
            ctx.unparse_principal(&*request.server)?
        };

        let (pa_rep_der, derived) = self
            .state
            .build_as_rep(
                &modreq.verified,
                nonce,
                enctype,
                req.request_packet,
                &client_name,
                &server_name,
                &o2k,
            )
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

    fn return_pkinit_kx(
        ctx: &PluginContext<'_>,
        req: &ReturnPadataRequest<'_>,
        callbacks: &KdcpreauthCallbacks<'_>,
    ) -> Result<Option<PaData>, Krb5Error> {
        let is_anonymous = callbacks
            .client_name_principal()
            .is_some_and(crate::principal::is_anonymous);
        if !is_anonymous {
            return Ok(None);
        }

        if req.reply.is_null() || req.encrypting_key.is_null() {
            return Err(Krb5Error::Custom(libc::EINVAL));
        }

        unsafe {
            let reply = &*req.reply;
            if reply.ticket.is_null() {
                return Err(Krb5Error::Custom(libc::EINVAL));
            }
            let ticket = &*reply.ticket;
            if ticket.enc_part2.is_null() {
                return Err(Krb5Error::Custom(libc::EINVAL));
            }
            let enc_tkt = &mut *ticket.enc_part2;
            if enc_tkt.session.is_null() {
                return Err(Krb5Error::Custom(libc::EINVAL));
            }
            let session = &*enc_tkt.session;

            let new_session = kurbu5_rs::crypto::fx_cf2_simple(
                ctx,
                session as *const _,
                c"PKINIT",
                req.encrypting_key as *const _,
                c"KEYEXCHANGE",
            )?;

            let key_data = std::slice::from_raw_parts(session.contents, session.length as usize);
            let enc_key = synta_krb5::kerberos_v5::EncryptionKey {
                keytype: synta_krb5::kerberos_v5::Int32::new_unchecked(session.enctype),
                keyvalue: OctetString::new(key_data.to_vec()),
            };
            let key_der = enc_key
                .to_der()
                .map_err(|_| Krb5Error::Custom(libc::EINVAL))?;

            let enc = kurbu5_rs::crypto::encrypt(
                ctx,
                req.encrypting_key as *const _,
                44, // KRB5_KEYUSAGE_PA_PKINIT_KX
                &key_der,
            )?;

            let enc_data = synta_krb5::kerberos_v5::EncryptedData {
                etype: synta_krb5::kerberos_v5::Int32::new_unchecked(enc.enctype),
                kvno: None,
                cipher: OctetString::new(enc.ciphertext),
            };
            let enc_data_der = enc_data
                .to_der()
                .map_err(|_| Krb5Error::Custom(libc::EINVAL))?;

            let ns = &*new_session;
            let session_mut = &mut *enc_tkt.session;
            if !session_mut.contents.is_null() && session_mut.length > 0 {
                std::ptr::write_bytes(session_mut.contents, 0, session_mut.length as usize);
            }
            kurbu5_sys::krb5_free_keyblock_contents(ctx.as_raw(), enc_tkt.session);
            session_mut.enctype = ns.enctype;
            session_mut.length = ns.length;
            let new_contents = libc::malloc(ns.length as usize) as *mut u8;
            if new_contents.is_null() {
                kurbu5_sys::krb5_free_keyblock(ctx.as_raw(), new_session);
                return Err(Krb5Error::Custom(libc::ENOMEM));
            }
            std::ptr::copy_nonoverlapping(ns.contents, new_contents, ns.length as usize);
            session_mut.contents = new_contents;

            kurbu5_sys::krb5_free_keyblock(ctx.as_raw(), new_session);

            Ok(Some(PaData::new(147, enc_data_der)))
        }
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
            pkinit_core::certauth::CertauthResult::Authorized => Ok(CertauthDecision::Authorized),
            pkinit_core::certauth::CertauthResult::AuthorizedHwauth => {
                Ok(CertauthDecision::AuthorizedHwauth)
            }
            pkinit_core::certauth::CertauthResult::NoOpinion => Ok(CertauthDecision::NoOpinion),
            pkinit_core::certauth::CertauthResult::Rejected(_) => Ok(CertauthDecision::NoOpinion),
        }
    }
}
