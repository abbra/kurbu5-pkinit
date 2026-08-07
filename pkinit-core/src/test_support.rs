//! Test-only helpers shared between this crate's unit tests and its
//! integration tests under `tests/`.

use std::sync::atomic::{AtomicI32, Ordering};

/// A fresh nonce for each exchange, instead of hardcoding the same literal
/// at every call site.
pub fn next_nonce() -> i32 {
    static NEXT: AtomicI32 = AtomicI32::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}
