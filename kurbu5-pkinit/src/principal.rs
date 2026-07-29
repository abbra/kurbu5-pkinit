use kurbu5_rs::PrincipalRef;

/// True if `p` is the RFC 8062 well-known anonymous principal
/// (`WELLKNOWN/ANONYMOUS`, two components, realm-agnostic).
pub(crate) fn is_anonymous(p: PrincipalRef<'_>) -> bool {
    p.components()
        .eq([b"WELLKNOWN".as_slice(), b"ANONYMOUS".as_slice()])
}
