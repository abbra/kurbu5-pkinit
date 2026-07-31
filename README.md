# kurbu5-pkinit

A Rust reimplementation of the MIT Kerberos PKINIT pre-authentication
mechanism (RFC 4556), built as a loadable MIT krb5 preauth plugin.

## Overview

The workspace is split into two crates:

- **`pkinit-core`** — a pure Rust library with no dependency on MIT krb5.
  It implements the PKINIT protocol state machines (client and KDC side),
  X.509/CMS handling, key derivation, and certificate-based authorization
  checks.
- **`kurbu5-pkinit`** — a thin `cdylib` adapter that bridges `pkinit-core`
  to MIT Kerberos via the [`kurbu5-rs`](https://crates.io/crates/kurbu5-rs)
  plugin bindings. It builds a single shared object exporting the
  `clpreauth`, `kdcpreauth`, and `certauth` plugin entry points.

ASN.1 encoding/decoding, X.509 parsing, and certificate chain validation are
provided by the [`synta`](https://crates.io/crates/synta) family of crates;
DH/ECDH key agreement and KDF primitives are provided by
[`native-ossl`](https://crates.io/crates/native-ossl).

## Features

- Core PKINIT (RFC 4556) with DH and elliptic-curve key exchange
- Anonymous PKINIT (RFC 6112 / RFC 8062, PA-PKINIT-KX)
- Algorithm-agile key derivation (RFC 8636 SP800-56A KDF), with fallback to
  the legacy `octetstring2key` derivation
- Post-quantum key exchange via ML-KEM-512/768/1024 (draft-ietf-kitten-pkinit-pqc),
  with ML-DSA-based downgrade prevention
- Freshness token support (RFC 8070) to mitigate AS-REQ replay
- Certificate-based client authorization: SAN, UPN, and EKU checks, CRL
  checking, and configurable minimum DH strength
- PKCS#11 hardware token support for identity keys, in addition to
  PEM/DER/PKCS#12 files

## Building

Prerequisites:

- A Rust toolchain with 2024 edition support (1.85+)
- MIT Kerberos development headers (`krb5-devel` / `libkrb5-dev`), 1.21+
- `libclang` (used by `bindgen` to generate the krb5 FFI bindings)
- OpenSSL development headers

```sh
cargo build --release
```

This produces `target/release/libkurbu5_pkinit.so`.

## Installing

Copy (or symlink) the built shared object into your krb5 plugin directory,
typically as `pkinit.so`:

```sh
install -m 755 target/release/libkurbu5_pkinit.so \
    /usr/lib64/krb5/plugins/preauth/pkinit.so
```

The plugin registers itself for both client (`kinit`) and KDC use; no
separate client/KDC builds are needed.

## Configuration

Configuration is read from `krb5.conf` using the standard `pkinit_*` options
under `[libdefaults]` / `[realms]` (client) and `[kdcdefaults]` / `[realms]`
(KDC):

| Option | Applies to | Purpose |
|---|---|---|
| `pkinit_identities` / `pkinit_identity` | client / KDC | Identity source (file, dir, PKCS#12, or PKCS#11 URI) |
| `pkinit_anchors` | both | Trusted CA certificates |
| `pkinit_pool` | both | Intermediate certificates |
| `pkinit_revoke` | both | CRLs |
| `pkinit_require_crl_checking` | both | Reject if no CRL is available for an anchor |
| `pkinit_dh_min_bits` | both | Minimum acceptable DH/EC group strength |
| `pkinit_eku_checking` | both | `kpClientAuth`, `scLogin`, or `none` |
| `pkinit_require_freshness_token` | both | Require an RFC 8070 freshness token |
| `pkinit_pqc_min_algorithm` | both | Minimum ML-KEM strength to offer/accept |
| `pkinit_allow_upn` | KDC | Accept Microsoft UPN SANs for client authorization |
| `pkinit_indicator` | KDC | Authentication indicators to attach on successful PKINIT |

## Testing

```sh
cargo test --workspace
```

runs the unit and protocol-level integration tests in `pkinit-core`. A full
system test that spins up an ephemeral KDC and exercises `kinit` against
this plugin (including cross-testing against the MIT `pkinit.so`) lives in
`tests/system/pkinit/run.sh`.

## License

Licensed under the MIT license — see [LICENSE](LICENSE).
