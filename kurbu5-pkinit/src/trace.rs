unsafe extern "C" {
    fn krb5int_trace(context: kurbu5_sys::krb5_context, fmt: *const std::ffi::c_char, ...);
}

pub(crate) fn trace(ctx: kurbu5_sys::krb5_context, msg: &str) {
    let Ok(cmsg) = std::ffi::CString::new(msg) else {
        return;
    };
    unsafe {
        krb5int_trace(ctx, c"{str}".as_ptr(), cmsg.as_ptr());
    }
}

macro_rules! pkinit_trace {
    ($ctx:expr, $($arg:tt)*) => {
        $crate::trace::trace($ctx.as_raw(), &format!($($arg)*))
    };
}
pub(crate) use pkinit_trace;
