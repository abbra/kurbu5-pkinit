
use kurbu5_rs::clpreauth::*;
use kurbu5_rs::{Krb5Error, PluginContext};
use pkinit_core::client::PkinitClientState;
use pkinit_core::config::PkinitClientConfig;
use pkinit_core::constants::{
    KRB5_PREAUTH_FAILED, PA_AS_FRESHNESS, PA_PKINIT_KX, PA_PK_AS_REP, PA_PK_AS_REQ,
};
use pkinit_core::identity::{IdentitySource, PkinitIdentity, TrustStore};

use crate::o2k::Krb5OctetString2Key;
use crate::profile;
use crate::trace::pkinit_trace;

pub struct PkinitClient {
    state: Option<PkinitClientState>,
    config: PkinitClientConfig,
}

impl ClpreauthModule for PkinitClient {
    const NAME: &'static std::ffi::CStr = c"pkinit";

    fn pa_type_list() -> &'static [i32] {
        static LIST: [i32; 5] = [PA_PK_AS_REP, PA_PK_AS_REQ, PA_PKINIT_KX, PA_AS_FRESHNESS, 0];
        &LIST
    }

    fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
        Ok(PkinitClient {
            state: None,
            config: PkinitClientConfig::default(),
        })
    }

    fn flags(_ctx: &PluginContext<'_>, pa_type: i32) -> i32 {
        match pa_type {
            PA_PK_AS_REQ | PA_PK_AS_REP => PA_REAL,
            PA_PKINIT_KX | PA_AS_FRESHNESS => PA_INFO,
            _ => 0,
        }
    }

    fn init_etype_info(
        &mut self,
        ctx: &PluginContext<'_>,
        _callbacks: &mut ClpreauthCallbacks<'_>,
        req: &EtypeInfoRequest<'_>,
    ) -> Result<(), Krb5Error> {
        if self.state.as_ref().is_some_and(|s| s.has_dh_key() || s.has_kem_key()) {
            return Ok(());
        }

        let is_anonymous = unsafe {
            let client_princ = (*req.request).client;
            if client_princ.is_null() {
                false
            } else {
                crate::principal::is_anonymous(kurbu5_rs::PrincipalRef::from(&*client_princ))
            }
        };

        let realm = ctx.realm().ok();
        let profile = kurbu5_rs::Profile::from_context(ctx)?;
        profile::read_client_config(&profile, realm.as_deref(), &mut self.config);

        let identity = if is_anonymous {
            pkinit_trace!(ctx, "PKINIT client using anonymous mode");
            PkinitIdentity {
                cert_der: vec![],
                key_pkcs8_der: vec![],
                chain: vec![],
            }
        } else {
            let identity_str = self.config.identity.as_deref().ok_or(Krb5Error::NoHandle)?;
            pkinit_trace!(ctx, "PKINIT loading identity {}", identity_str);
            let source =
                IdentitySource::parse(identity_str).map_err(|_| Krb5Error::Custom(libc::EINVAL))?;
            let id = PkinitIdentity::load(&source).map_err(|_| Krb5Error::Custom(libc::EINVAL))?;
            pkinit_trace!(ctx, "PKINIT loaded cert and key for {}", identity_str);
            id
        };

        let mut trust_store = TrustStore::new();
        for anchor in &self.config.anchors {
            pkinit_trace!(ctx, "PKINIT loading CA certs and CRLs from {}", anchor);
            trust_store
                .load_from_path(anchor)
                .map_err(|_| Krb5Error::Custom(libc::EINVAL))?;
        }

        let mut client = PkinitClientState::new(identity, trust_store, self.config.clone());

        let server_princ = unsafe { (*req.request).server };
        if !server_princ.is_null() {
            let server_ref = unsafe { &*server_princ };
            if let Ok(princ_str) = ctx.unparse_principal(server_ref) {
                client.set_kdc_identity(princ_str, None);
            }
        }

        self.state = Some(client);
        Ok(())
    }

    fn process(
        &mut self,
        ctx: &PluginContext<'_>,
        callbacks: &mut ClpreauthCallbacks<'_>,
        req: &ProcessRequest<'_>,
    ) -> Result<Vec<PaData>, Krb5Error> {
        let pa_type = req.pa_data.pa_type;
        match pa_type {
            PA_PKINIT_KX => {
                pkinit_trace!(ctx, "PKINIT client received RFC 6112 support from KDC");
                Ok(vec![])
            }
            PA_AS_FRESHNESS => {
                pkinit_trace!(ctx, "PKINIT client received freshness token from KDC");
                let contents = pa_data_contents(req.pa_data);
                if let Some(state) = &mut self.state {
                    state.set_freshness_token(contents);
                }
                Ok(vec![])
            }
            PA_PK_AS_REQ => {
                let state = self.state.as_mut().ok_or(Krb5Error::Custom(libc::EINVAL))?;

                let hint_contents = pa_data_contents(req.pa_data);
                if !hint_contents.is_empty() {
                    let _ = state.process_pkinit_hint(&hint_contents);
                }

                pkinit_trace!(ctx, "PKINIT client making DH request");

                let nonce = unsafe { (*req.request).nonce };
                let (ctime, cusec) = callbacks.get_preauth_time(true)?;

                let req_body_der = req
                    .encoded_request_body
                    .ok_or(Krb5Error::Custom(libc::EINVAL))?;

                let pa_req_der = state
                    .build_as_req(nonce, ctime as i64, cusec, req_body_der)
                    .map_err(|e| {
                        pkinit_trace!(ctx, "PKINIT client failed to build AS-REQ: {}", e);
                        Krb5Error::Custom(libc::EINVAL)
                    })?;

                Ok(vec![PaData::new(PA_PK_AS_REQ, pa_req_der)])
            }
            PA_PK_AS_REP => {
                pkinit_trace!(ctx, "PKINIT client processing AS-REP");
                let state = self.state.as_mut().ok_or(Krb5Error::Custom(libc::EINVAL))?;

                let nonce = unsafe { (*req.request).nonce };
                let enctype = callbacks.get_etype();
                let pa_contents = pa_data_contents(req.pa_data);
                if pa_contents.is_empty() {
                    return Err(Krb5Error::Custom(libc::EINVAL));
                }

                let as_req_der = req.encoded_previous_request.unwrap_or(b"");

                let client_name = unsafe {
                    let request = &*req.request;
                    if request.client.is_null() {
                        return Err(Krb5Error::Custom(libc::EINVAL));
                    }
                    ctx.unparse_principal(&*request.client)?
                };
                let server_name = unsafe {
                    let request = &*req.request;
                    if request.server.is_null() {
                        return Err(Krb5Error::Custom(libc::EINVAL));
                    }
                    ctx.unparse_principal(&*request.server)?
                };

                let o2k = Krb5OctetString2Key::new(ctx);
                let derived = state
                    .process_as_rep(
                        &pa_contents,
                        &pkinit_core::client::AsRepParams {
                            nonce,
                            enctype,
                            as_req_der,
                            pa_rep_raw: &pa_contents,
                            client_name: &client_name,
                            server_name: &server_name,
                        },
                        &o2k,
                    )
                    .map_err(|e| {
                        pkinit_trace!(ctx, "PKINIT client could not verify reply: {}", e);
                        Krb5Error::Custom(libc::EINVAL)
                    })?;
                pkinit_trace!(ctx, "PKINIT client verified DH reply");

                let mut keyblock = kurbu5_sys::krb5_keyblock {
                    magic: 0,
                    enctype: derived.enctype,
                    length: derived.key_data.len() as u32,
                    contents: derived.key_data.as_ptr() as *mut u8,
                };
                let key_ref = unsafe { KeyblockRef::from_raw(&mut keyblock) };
                callbacks.set_as_key(&key_ref)?;

                Ok(vec![])
            }
            _ => Err(Krb5Error::NoHandle),
        }
    }

    fn supply_gic_opts(
        &mut self,
        ctx: &PluginContext<'_>,
        _opt: *mut kurbu5_sys::krb5_get_init_creds_opt,
        attr: &str,
        value: &str,
    ) -> Result<(), Krb5Error> {
        match attr {
            "X509_user_identity" => {
                if self.config.identity.is_some() {
                    return Err(Krb5Error::Custom(KRB5_PREAUTH_FAILED));
                }
                pkinit_trace!(ctx, "PKINIT received -X {}={}", attr, value);
                self.config.identity = Some(value.to_string());
            }
            "X509_anchors" => {
                pkinit_trace!(ctx, "PKINIT received -X {}={}", attr, value);
                self.config.anchors.push(value.to_string());
            }
            "disable_freshness"
                if matches!(
                    value.to_ascii_lowercase().as_str(),
                    "yes" | "true" | "1"
                ) =>
            {
                pkinit_trace!(ctx, "PKINIT received -X {}={}", attr, value);
                self.config.disable_freshness = true;
            }
            _ => {}
        }
        Ok(())
    }

    fn tryagain(
        &mut self,
        ctx: &PluginContext<'_>,
        _callbacks: &mut ClpreauthCallbacks<'_>,
        req: &TryagainRequest<'_>,
    ) -> Result<Vec<PaData>, Krb5Error> {
        pkinit_trace!(
            ctx,
            "PKINIT client trying again with KDC-provided parameters"
        );
        let state = self.state.as_mut().ok_or(Krb5Error::NoHandle)?;

        if req.error_padata.is_null() {
            return Ok(vec![]);
        }
        let error_padata_ptr = unsafe { *req.error_padata };
        if error_padata_ptr.is_null() {
            return Ok(vec![]);
        }

        let error_pa = unsafe { &*error_padata_ptr };
        if error_pa.contents.is_null() || error_pa.length == 0 {
            return Ok(vec![]);
        }

        let error_data =
            unsafe { std::slice::from_raw_parts(error_pa.contents, error_pa.length as usize) };

        let _action = state
            .handle_tryagain(error_data)
            .map_err(|_| Krb5Error::NoHandle)?;

        Ok(vec![])
    }
}

fn pa_data_contents(pa: &kurbu5_sys::krb5_pa_data) -> Vec<u8> {
    if pa.contents.is_null() || pa.length == 0 {
        vec![]
    } else {
        unsafe { std::slice::from_raw_parts(pa.contents, pa.length as usize).to_vec() }
    }
}
