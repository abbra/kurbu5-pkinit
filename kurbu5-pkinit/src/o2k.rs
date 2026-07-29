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

    fn krb5_free_keyblock_contents(
        context: kurbu5_sys::krb5_context,
        keyblock: *mut kurbu5_sys::krb5_keyblock,
    );
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
        let seed = kurbu5_sys::krb5_data {
            magic: 0,
            length: random_data.len() as u32,
            data: random_data.as_ptr() as *mut _,
        };
        let mut keyblock = kurbu5_sys::krb5_keyblock {
            magic: 0,
            enctype,
            length: 0,
            contents: std::ptr::null_mut(),
        };

        let ret = unsafe { krb5_c_random_to_key(self.ctx, enctype, &seed, &mut keyblock) };
        if ret != 0 {
            return Err(PkinitError::KdfFailed(format!(
                "krb5_c_random_to_key failed: {ret}"
            )));
        }

        let key_data = if !keyblock.contents.is_null() && keyblock.length > 0 {
            unsafe {
                std::slice::from_raw_parts(keyblock.contents, keyblock.length as usize).to_vec()
            }
        } else {
            return Err(PkinitError::KdfFailed(
                "krb5_c_random_to_key returned empty key".into(),
            ));
        };

        unsafe { krb5_free_keyblock_contents(self.ctx, &mut keyblock) };
        Ok(key_data)
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
