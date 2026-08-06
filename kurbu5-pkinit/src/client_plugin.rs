use kurbu5_rs::clpreauth::*;
use kurbu5_rs::{Krb5Error, PluginContext};
use pkinit_core::client::PkinitClientState;
use pkinit_core::config::PkinitClientConfig;
use pkinit_core::constants::{
    KRB5_PREAUTH_FAILED, PA_AS_FRESHNESS, PA_PK_AS_REP, PA_PK_AS_REQ, PA_PKINIT_KX,
};
use pkinit_core::error::PkinitError;
use pkinit_core::identity::{IdentitySource, PkinitIdentity, TrustStore};
use std::path::PathBuf;

use crate::o2k::Krb5OctetString2Key;
use crate::profile;
use crate::trace::pkinit_trace;

/// Responder question key asked when a configured PKCS#12 identity file
/// needs a password that the initial empty-password attempt didn't satisfy.
/// Answered through the krb5 responder interface (e.g. an application's
/// `krb5_get_init_creds_opt_set_responder` callback) — `kinit`'s own command
/// line has no way to answer arbitrary responder questions, so a
/// non-interactive `kinit` invocation against an encrypted PKCS#12 file
/// will fail with a clear error instead of silently trying an empty password.
const PKCS12_PASSWORD_QUESTION: &str = "pkinit_pkcs12_password";

/// A PKCS#12 identity load that's waiting on a password from the responder.
/// Everything needed to finish building `PkinitClientState` once the answer
/// arrives, computed once in `init_etype_info` so it isn't redone in `process`.
struct PendingPkcs12 {
    path: PathBuf,
    trust_store: TrustStore,
    server_principal: Option<String>,
}

pub struct PkinitClient {
    state: Option<PkinitClientState>,
    config: PkinitClientConfig,
    pending_pkcs12: Option<PendingPkcs12>,
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
            pending_pkcs12: None,
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
        callbacks: &mut ClpreauthCallbacks<'_>,
        req: &EtypeInfoRequest<'_>,
    ) -> Result<(), Krb5Error> {
        if self
            .state
            .as_ref()
            .is_some_and(|s| s.has_dh_key() || s.has_kem_key())
        {
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

        let mut trust_store = TrustStore::new();
        for anchor in &self.config.anchors {
            pkinit_trace!(ctx, "PKINIT loading CA certs and CRLs from {}", anchor);
            trust_store
                .load_from_path(anchor)
                .map_err(|_| Krb5Error::Custom(libc::EINVAL))?;
        }

        let server_principal = unsafe {
            let server_princ = (*req.request).server;
            if server_princ.is_null() {
                None
            } else {
                ctx.unparse_principal(&*server_princ).ok()
            }
        };

        if is_anonymous {
            pkinit_trace!(ctx, "PKINIT client using anonymous mode");
            let identity = PkinitIdentity {
                cert_der: vec![],
                key_pkcs8_der: vec![],
                chain: vec![],
            };
            self.state = Some(build_client(
                identity,
                trust_store,
                self.config.clone(),
                server_principal,
            ));
            return Ok(());
        }

        let identity_str = self.config.identity.as_deref().ok_or(Krb5Error::NoHandle)?;
        pkinit_trace!(ctx, "PKINIT loading identity {}", identity_str);
        let source =
            IdentitySource::parse(identity_str).map_err(|_| Krb5Error::Custom(libc::EINVAL))?;

        match PkinitIdentity::load(&source) {
            Ok(identity) => {
                pkinit_trace!(ctx, "PKINIT loaded cert and key for {}", identity_str);
                self.state = Some(build_client(
                    identity,
                    trust_store,
                    self.config.clone(),
                    server_principal,
                ));
                self.pending_pkcs12 = None;
            }
            Err(PkinitError::Pkcs12PasswordRequired) => {
                let IdentitySource::Pkcs12 { path } = &source else {
                    return Err(Krb5Error::Custom(libc::EINVAL));
                };
                pkinit_trace!(
                    ctx,
                    "PKINIT PKCS#12 {} requires a password; asking responder",
                    path.display()
                );
                callbacks
                    .ask_responder_question(PKCS12_PASSWORD_QUESTION, &path.display().to_string())
                    .map_err(|_| Krb5Error::Custom(libc::EINVAL))?;
                self.pending_pkcs12 = Some(PendingPkcs12 {
                    path: path.clone(),
                    trust_store,
                    server_principal,
                });
            }
            Err(_) => return Err(Krb5Error::Custom(libc::EINVAL)),
        }

        Ok(())
    }

    fn process(
        &mut self,
        ctx: &PluginContext<'_>,
        callbacks: &mut ClpreauthCallbacks<'_>,
        req: &ProcessRequest<'_>,
    ) -> Result<Vec<PaData>, Krb5Error> {
        self.finish_pending_pkcs12(ctx, callbacks)?;

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

                pkinit_trace!(ctx, "PKINIT client building AS-REQ");

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

                if let Some(key_exchange) = state.key_exchange() {
                    pkinit_trace!(ctx, "PKINIT client selected {}", key_exchange);
                }

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
                match state.key_exchange() {
                    Some(key_exchange) => {
                        pkinit_trace!(ctx, "PKINIT client verified AS-REP via {}", key_exchange)
                    }
                    None => pkinit_trace!(ctx, "PKINIT client verified AS-REP"),
                }

                let key_bytes = derived.key_data.as_ref();
                let mut keyblock = kurbu5_sys::krb5_keyblock {
                    magic: 0,
                    enctype: derived.enctype,
                    length: key_bytes.len() as u32,
                    contents: key_bytes.as_ptr() as *mut u8,
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
                if matches!(value.to_ascii_lowercase().as_str(), "yes" | "true" | "1") =>
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

impl PkinitClient {
    /// Finish building `self.state` from a PKCS#12 identity that was waiting
    /// on a password (see `init_etype_info`). A no-op if nothing is pending.
    ///
    /// Per the krb5 clpreauth architecture, all modules' `prep_questions`
    /// (`init_etype_info`) callbacks run before the application's responder
    /// is consulted, which in turn runs before any module's `process` is
    /// called — so by the time this runs, `get_responder_answer` already has
    /// whatever the responder supplied for the question asked above.
    fn finish_pending_pkcs12(
        &mut self,
        ctx: &PluginContext<'_>,
        callbacks: &mut ClpreauthCallbacks<'_>,
    ) -> Result<(), Krb5Error> {
        let Some(pending) = self.pending_pkcs12.take() else {
            return Ok(());
        };

        let password = callbacks
            .get_responder_answer(PKCS12_PASSWORD_QUESTION)
            .ok_or_else(|| {
                pkinit_trace!(
                    ctx,
                    "PKINIT PKCS#12 {} needs a password but none was supplied",
                    pending.path.display()
                );
                Krb5Error::Custom(libc::EINVAL)
            })?;

        let identity = PkinitIdentity::load_pkcs12(&pending.path, password.as_bytes())
            .map_err(|_| Krb5Error::Custom(libc::EINVAL))?;
        pkinit_trace!(
            ctx,
            "PKINIT loaded PKCS#12 identity {} with supplied password",
            pending.path.display()
        );

        self.state = Some(build_client(
            identity,
            pending.trust_store,
            self.config.clone(),
            pending.server_principal,
        ));
        Ok(())
    }
}

/// Build a `PkinitClientState` and apply the KDC identity, shared by the
/// happy path (`init_etype_info`) and the deferred PKCS#12-password path
/// (`finish_pending_pkcs12`).
fn build_client(
    identity: PkinitIdentity,
    trust_store: TrustStore,
    config: PkinitClientConfig,
    server_principal: Option<String>,
) -> PkinitClientState {
    let mut client = PkinitClientState::new(identity, trust_store, config);
    if let Some(principal) = server_principal {
        client.set_kdc_identity(principal, None);
    }
    client
}

fn pa_data_contents(pa: &kurbu5_sys::krb5_pa_data) -> Vec<u8> {
    if pa.contents.is_null() || pa.length == 0 {
        vec![]
    } else {
        unsafe { std::slice::from_raw_parts(pa.contents, pa.length as usize).to_vec() }
    }
}
