use std::marker::PhantomData;

use kurbu5_rs::clpreauth::*;
use kurbu5_rs::{Krb5Error, PluginContext};
use pkinit_core::client::PkinitClientState;
use pkinit_core::config::PkinitClientConfig;
use pkinit_core::identity::{IdentitySource, PkinitIdentity, TrustStore};

use crate::o2k::Krb5OctetString2Key;
use crate::profile;

pub struct PkinitClient {
    state: Option<PkinitClientState>,
    config: PkinitClientConfig,
}

impl ClpreauthModule for PkinitClient {
    const NAME: &'static std::ffi::CStr = c"pkinit";

    fn pa_type_list() -> &'static [i32] {
        static LIST: [i32; 5] = [17, 16, 147, 150, 0];
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
            16 | 17 => PA_REAL,
            147 | 150 => PA_INFO,
            _ => 0,
        }
    }

    fn init_etype_info(
        &mut self,
        ctx: &PluginContext<'_>,
        _callbacks: &mut ClpreauthCallbacks<'_>,
        req: &EtypeInfoRequest<'_>,
    ) -> Result<(), Krb5Error> {
        if self.state.as_ref().is_some_and(|s| s.has_dh_key()) {
            return Ok(());
        }

        let realm = ctx.realm().ok();
        let profile = kurbu5_rs::Profile::from_context(ctx)?;
        self.config = profile::read_client_config(&profile, realm.as_deref());

        let identity_str = self.config.identity.as_deref().ok_or(Krb5Error::NoHandle)?;

        let source =
            IdentitySource::parse(identity_str).map_err(|_| Krb5Error::Custom(libc::EINVAL))?;
        let identity =
            PkinitIdentity::load(&source).map_err(|_| Krb5Error::Custom(libc::EINVAL))?;

        let mut trust_store = TrustStore::new();
        for anchor in &self.config.anchors {
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
            147 => {
                if let Some(state) = &mut self.state {
                    state.set_rfc6112_kdc(true);
                }
                Ok(vec![])
            }
            150 => {
                let contents = pa_data_contents(req.pa_data);
                if let Some(state) = &mut self.state {
                    state.set_freshness_token(contents);
                }
                Ok(vec![])
            }
            16 => {
                let state = self
                    .state
                    .as_mut()
                    .ok_or(Krb5Error::Custom(libc::EINVAL))?;

                let nonce = unsafe { (*req.request).nonce };
                let (ctime, cusec) = callbacks.get_preauth_time(true)?;

                let req_body_der = req
                    .encoded_request_body
                    .ok_or(Krb5Error::Custom(libc::EINVAL))?;

                let pa_req_der = state
                    .build_as_req(nonce, ctime as i64, cusec, req_body_der)
                    .map_err(|_| Krb5Error::Custom(libc::EINVAL))?;

                Ok(vec![PaData::new(16, pa_req_der)])
            }
            17 => {
                let state = self
                    .state
                    .as_mut()
                    .ok_or(Krb5Error::Custom(libc::EINVAL))?;

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
                        nonce,
                        enctype,
                        as_req_der,
                        &pa_contents,
                        &client_name,
                        &server_name,
                        &o2k,
                    )
                    .map_err(|_| Krb5Error::Custom(libc::EINVAL))?;

                let mut keyblock = kurbu5_sys::krb5_keyblock {
                    magic: 0,
                    enctype: derived.enctype,
                    length: derived.key_data.len() as u32,
                    contents: derived.key_data.as_ptr() as *mut u8,
                };
                // KeyblockRef is { ptr: *mut krb5_keyblock, _phantom: PhantomData }
                // and set_as_key copies the key contents, so the stack keyblock
                // only needs to survive this call.
                let key_ref: KeyblockRef<'_> = unsafe {
                    std::mem::transmute((
                        &mut keyblock as *mut kurbu5_sys::krb5_keyblock,
                        PhantomData::<&()>,
                    ))
                };
                callbacks.set_as_key(&key_ref)?;

                Ok(vec![])
            }
            _ => Err(Krb5Error::NoHandle),
        }
    }

    fn tryagain(
        &mut self,
        _ctx: &PluginContext<'_>,
        _callbacks: &mut ClpreauthCallbacks<'_>,
        req: &TryagainRequest<'_>,
    ) -> Result<Vec<PaData>, Krb5Error> {
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
