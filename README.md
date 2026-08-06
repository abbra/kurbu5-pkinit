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

- Core PKINIT with DH and elliptic-curve key exchange, for both `kinit`
  (client) and the KDC
- Anonymous PKINIT (PA-PKINIT-KX)
- Algorithm-agile key derivation, with fallback to the legacy
  `octetstring2key` derivation for peers that don't negotiate a KDF
- Post-quantum key exchange via ML-KEM-512/768/1024, with ML-DSA-based
  downgrade prevention
- Freshness token support to mitigate AS-REQ replay
- Certificate-based client authorization: SAN, UPN, and EKU checks, CRL
  checking, and configurable minimum DH/EC group strength
- Identity loading from PEM/DER files, PKCS#12 bundles, or a PKCS#11
  hardware token URI
- Interop-tested against the stock MIT `pkinit.so` in both client and KDC
  roles (see [Testing](#testing))

## Supported RFCs and Internet-Drafts

### RFCs

| RFC | Role |
|---|---|
| [RFC 3526](https://www.rfc-editor.org/rfc/rfc3526) | More MODP Diffie-Hellman groups — Oakley 2048-bit and 4096-bit groups |
| [RFC 4556](https://www.rfc-editor.org/rfc/rfc4556) | PKINIT — core protocol: PA-PK-AS-REQ/REP, DH/EC key exchange, legacy key derivation |
| [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) | X.509 PKI certificate and CRL profile — chain/path validation |
| [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652) | Cryptographic Message Syntax — SignedData for AuthPack/KDCDHKeyInfo, including the unsigned variant used for anonymous PKINIT |
| [RFC 6112](https://www.rfc-editor.org/rfc/rfc6112) | Anonymous PKINIT — PA-PKINIT-KX |
| [RFC 8062](https://www.rfc-editor.org/rfc/rfc8062) | Anonymous Kerberos — `WELLKNOWN/ANONYMOUS` principal handling |
| [RFC 8070](https://www.rfc-editor.org/rfc/rfc8070) | Kerberos Pre-Authentication Freshness — PA-AS-FRESHNESS |
| [RFC 8636](https://www.rfc-editor.org/rfc/rfc8636) | PKINIT Algorithm Agility — SP800-56A KDF and its negotiation |
| [RFC 9935](https://www.rfc-editor.org/rfc/rfc9935) | AlgorithmIdentifier encodings for ML-KEM/ML-DSA, used for the PQC OIDs |

### Internet-Drafts

| Draft | Role |
|---|---|
| [draft-bokovoy-kitten-pkinit-pqc](https://datatracker.ietf.org/doc/draft-bokovoy-kitten-pkinit-pqc/) | Post-quantum PKINIT key exchange via ML-KEM, with ML-DSA-based downgrade prevention |

### Other standards

| Standard | Role |
|---|---|
| FIPS 203 (ML-KEM) | Post-quantum key encapsulation mechanism (512/768/1024) |
| FIPS 204 (ML-DSA) | Post-quantum signatures, used for downgrade-prevention checks on KDC certificates |
| NIST SP 800-56A | Single-step concatenation KDF underlying RFC 8636 |

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
| `pkinit_identities` / `pkinit_identity` | client / KDC | Identity source (file, dir, PKCS#12, or PKCS#11 URI). A password-protected PKCS#12 file is never given a password in this setting — the client asks for one via the krb5 responder interface (question key `pkinit_pkcs12_password`); callers that don't register a responder (e.g. plain `kinit`) will get a clear failure instead of a silent empty-password attempt. |
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
