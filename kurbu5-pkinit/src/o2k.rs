use pkinit_core::error::PkinitError;
use pkinit_core::crypto::kdf::OctetString2Key;

unsafe extern "C" {
    fn krb5_c_random_to_key(
        context: kurbu5_sys::krb5_context,
        enctype: kurbu5_sys::krb5_enctype,
        seed: *const kurbu5_sys::krb5_data,
        keyblock: *mut kurbu5_sys::krb5_keyblock,
    ) -> kurbu5_sys::krb5_error_code;

    fn krb5_c_keylengths(
        context: kurbu5_sys::krb5_context,
        enctype: kurbu5_sys::krb5_enctype,
        keybytes: *mut usize,
        keylength: *mut usize,
    ) -> kurbu5_sys::krb5_error_code;
}

pub struct Krb5OctetString2Key {
    ctx: kurbu5_sys::krb5_context,
}

impl Krb5OctetString2Key {
    pub fn new(ctx: &kurbu5_rs::PluginContext<'_>) -> Self {
        Self {
            ctx: ctx.as_raw(),
        }
    }
}

impl OctetString2Key for Krb5OctetString2Key {
    fn random_to_key(&self, enctype: i32, random_data: &[u8]) -> Result<Vec<u8>, PkinitError> {
        let keylength = self.key_length(enctype)?;

        let seed = kurbu5_sys::krb5_data {
            magic: 0,
            length: random_data.len() as u32,
            data: random_data.as_ptr() as *mut _,
        };

        let mut key_buf = vec![0u8; keylength];
        let mut keyblock = kurbu5_sys::krb5_keyblock {
            magic: 0,
            enctype,
            length: keylength as u32,
            contents: key_buf.as_mut_ptr(),
        };

        let ret = unsafe { krb5_c_random_to_key(self.ctx, enctype, &seed, &mut keyblock) };
        if ret != 0 {
            return Err(PkinitError::KdfFailed(format!(
                "krb5_c_random_to_key failed: {ret}"
            )));
        }

        Ok(key_buf)
    }

    fn random_length(&self, enctype: i32) -> Result<usize, PkinitError> {
        let mut keybytes: usize = 0;
        let mut _keylength: usize = 0;
        let ret = unsafe {
            krb5_c_keylengths(self.ctx, enctype, &mut keybytes, &mut _keylength)
        };
        if ret != 0 {
            return Err(PkinitError::KdfFailed(format!(
                "krb5_c_keylengths failed: {ret}"
            )));
        }
        Ok(keybytes)
    }

    fn key_length(&self, enctype: i32) -> Result<usize, PkinitError> {
        let mut _keybytes: usize = 0;
        let mut keylength: usize = 0;
        let ret = unsafe {
            krb5_c_keylengths(self.ctx, enctype, &mut _keybytes, &mut keylength)
        };
        if ret != 0 {
            return Err(PkinitError::KdfFailed(format!(
                "krb5_c_keylengths failed: {ret}"
            )));
        }
        Ok(keylength)
    }
}
