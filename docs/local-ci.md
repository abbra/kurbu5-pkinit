# Local CI and the interactive playground

`contrib/ci/local-ci.sh` does two things:

- it runs the CI pipeline on your machine, mirroring
  `.github/workflows/ci.yml` job for job, and
- its `interactive` target starts a throwaway Kerberos realm with a
  kurbu5-pkinit KDC (and, by default, the trust broker), then drops you into a
  shell inside it so you can try PKINIT by hand.

This document covers both. For the plugin's own configuration options, see the
top-level [README](../README.md).

- [Prerequisites](#prerequisites)
- [Running CI jobs](#running-ci-jobs)
- [The interactive playground](#the-interactive-playground)
  - [What it sets up](#what-it-sets-up)
  - [Options](#options)
  - [Inside the playground shell](#inside-the-playground-shell)
  - [Recipes](#recipes)
  - [Client identity on a PKCS#11 token](#client-identity-on-a-pkcs11-token)
  - [Troubleshooting](#troubleshooting)

## Prerequisites

The script needs bash 4 or later and checks for its tools at startup, printing
`✓` for what it found and `○` for what is missing:

| Tool | Needed for |
| --- | --- |
| `cargo` | everything |
| `rustfmt`, `clippy` | the `fmt` and `clippy` jobs (`rustup component add rustfmt clippy`) |
| `krb5kdc`, `kinit`, `kadmin.local` (MIT krb5 1.22 or later) | `system-test`, `tofu-test`, `interactive` (Fedora: `krb5-server`, `krb5-workstation`) |
| `openssl` | `system-test`, `tofu-test`, `interactive` |
| `python3` | `system-test`, `tofu-test`, `interactive` |
| `valgrind` | `--valgrind` only |
| `actionlint` (or `yamllint` as a fallback) | `lint-workflows`; skipped with a warning if neither is installed |

The key exchange is ML-KEM by default and the `mldsa*` key types use ML-DSA,
so OpenSSL 3.5 or later is needed.

Token mode in the playground has extra requirements; see
[Client identity on a PKCS#11 token](#client-identity-on-a-pkcs11-token).

## Running CI jobs

```sh
./contrib/ci/local-ci.sh all                 # every job, in order
./contrib/ci/local-ci.sh build fmt clippy    # just these
./contrib/ci/local-ci.sh --list              # job names
```

| Job | What it runs | Depends on |
| --- | --- | --- |
| `build` | `cargo build --workspace` | |
| `fmt` | `cargo fmt --all -- --check` | |
| `lint-workflows` | `actionlint` (or `yamllint`) on `.github/workflows/*.yml` | |
| `clippy` | `cargo clippy --workspace --all-features -- -D warnings` | `build` |
| `doc` | `cargo doc --workspace --no-deps --all-features`, with `RUSTDOCFLAGS=-D warnings` | `build` |
| `test` | `cargo test --workspace --all-features` | `build` |
| `system-test` | `tests/system/pkinit/run.sh`: `kinit` against an ephemeral KDC, cross-tested with MIT's `pkinit.so` (us-us, us-mit, mit-us, mit-mit). us-us uses an ML-KEM-768 key exchange; the combos involving MIT use classic DH/ECDH, which is all MIT's `pkinit.so` supports | `build` |
| `tofu-test` | `tests/system/pkinit/tofu.sh`: KDC-CA trust-on-first-use scenarios (happy path, denial, MITM, ML-DSA chain, tty prompt), with an HTML report | `build` |

Dependencies mirror the workflow's `needs:` fields. When you ask for a job
whose prerequisite has not run yet, the script runs the prerequisite first. If
a prerequisite fails, the job is reported as `SKIP`. A summary table and the
total time are printed at the end, and the exit status is non-zero if any job
failed.

Global options go **before** the job names:

| Option | Effect |
| --- | --- |
| `--no-color` | Disable ANSI colour (same as `NO_COLOR=1`). |
| `--no-deps` | Don't run or check prerequisites. Use it in CI systems that already order jobs (`needs:`). |
| `--valgrind` | Run Rust test binaries under Valgrind with full leak checking and `contrib/ci/rust-valgrind.supp`. Affects the `test` job. |

Set `CARGO_TARGET_DIR` to build into a separate directory, e.g. to avoid
contending with your editor's build:

```sh
CARGO_TARGET_DIR=/tmp/kurbu5-pkinit-target ./contrib/ci/local-ci.sh all
```

## The interactive playground

```sh
./contrib/ci/local-ci.sh interactive [OPTIONS]
./contrib/ci/local-ci.sh interactive --help
```

### What it sets up

1. Builds `kurbu5-pkinit`, `pkinit-trust-brokerd` and `pkinit-trust-ctl` in
   release mode.
2. Creates a work directory, `/tmp/pkinit-playground.XXXXXXXXXX`.
3. Unless `--no-tofu` is given, starts `pkinit-trust-brokerd` in its own
   session (`setsid`), listening on `trust.sock` in the work directory and
   persisting its decisions to `trust.state.json`.
4. Runs `tests/system/pkinit/setup.py`, which:
   - generates a test PKI: a CA, a KDC certificate, and (except in token mode)
     a client certificate with a KRB5 principal SAN, all signed with
     `--key-type` and valid for one day;
   - writes `krb5.conf` and `kdc.conf` that load kurbu5-pkinit as the
     `kdcpreauth`, `clpreauth` and `certauth` module, with
     `pkinit_pqc_min_algorithm` (ML-KEM-768 unless `--pqc-min-algorithm`
     says otherwise) and `pkinit_require_kem = true` on both sides, so a
     classic DH/ECDH exchange is refused;
   - creates the realm database, the client principal (no password, PKINIT
     only) and `WELLKNOWN/ANONYMOUS`;
   - starts `krb5kdc` listening only on a UNIX domain socket,
     `/tmp/pkinit-kdc-XXXXXXXX/kdc.sock`, and points the realm's `kdc` at it
     (MIT krb5 1.22+). No TCP or UDP port is opened, so any number of
     playgrounds and test runs can coexist on one machine;
   - writes an environment file that the script sources.
5. Prints a summary of the configuration and some commands to try, then starts
   your `$SHELL` with the prompt `[pkinit-playground] \W $`.

Exiting the shell (`exit` or Ctrl-D), or interrupting startup with Ctrl-C,
stops the KDC and the broker and deletes the work directory. Nothing outside
the work directory is touched.

How the client trusts the KDC depends on the mode:

- **TOFU (default).** The client has no static anchor for the KDC's CA. Its
  realm stanza sets `auto_fast_armor = true`, `pkinit_kdc_trust_tofu = true`
  and `pkinit_kdc_trust_broker = <socket>`, so the first `kinit` runs an
  anonymous exchange, the broker asks you whether to trust the CA, and the
  authenticated exchange then validates against the CA you approved. The KDC
  sends its CA along with its certificate so there is a CA to pin.
- **Static anchors (`--no-tofu`).** The client gets
  `pkinit_anchors = FILE:<ca.pem>` and no broker is started.

### Options

| Option | Default | Description |
| --- | --- | --- |
| `--key-type TYPE` | `ec:P-256` | Algorithm of the CA, KDC and client certificates: `ec:P-256`, `ec:P-384`, `ec:P-521`, `rsa:2048`, `rsa:3072`, `rsa:4096`, `mldsa44`, `mldsa65`, `mldsa87`. This only decides what signs the certificates, not the key exchange. |
| `--pqc-min-algorithm ALG` | `ML-KEM-768` | Minimum ML-KEM algorithm for the key exchange, set as `pkinit_pqc_min_algorithm` on both sides together with `pkinit_require_kem = true`: `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024`, `ML-KEM-768-X25519`, `ML-KEM-768-ECDH-P256`, `ML-KEM-1024-ECDH-P384`. `none` selects classic DH/ECDH instead. |
| `--realm REALM` | `PKINIT.TEST` | Realm name. In token mode, defaults to the realm in the token certificate's SAN. |
| `--principal NAME` | `user` | Client principal. In token mode, defaults to the principal in the token certificate's SAN. |
| `--no-tofu` | TOFU on | Skip the broker and give the client a static `pkinit_anchors`. |
| `--ui MODE` | `auto` | How the broker prompts: `gui` (desktop notification), `tty` (the terminal of the `kinit` that asked), or `auto` (notification when `$DISPLAY`/`$WAYLAND_DISPLAY` is set, terminal otherwise). Ignored with `--no-tofu`. |
| `--token URI` | unset | Use a certificate and key on a PKCS#11 token as the client identity. See [below](#client-identity-on-a-pkcs11-token). |
| `--client-ca FILE` | issuer found on the token | PEM of the CA that issued the token certificate. Token mode only. |
| `--pkcs11-module FILE` | p11-kit proxy | PKCS#11 module to load through the OpenSSL pkcs11-provider. Token mode only. |

The key exchange is post-quantum by default, whatever certificates
`--key-type` produces: RSA and ECDSA certificates still get an ML-KEM
exchange. `--key-type` and `--pqc-min-algorithm` are independent. Use
`--pqc-min-algorithm none` only to look at a classic DH/ECDH exchange, the
only kind MIT's own `pkinit.so` can negotiate.

### Inside the playground shell

The environment file exports:

| Variable | Value |
| --- | --- |
| `KRB5_CONFIG`, `KRB5_KDC_PROFILE` | the generated `krb5.conf` and `kdc.conf` |
| `KRB5CCNAME` | `FILE:<testdir>/ccache` |
| `KRB5RCACHEDIR` | the test directory |
| `KRB5_TRACE` | `<testdir>/client-trace.log`, the client-side libkrb5 and plugin trace |
| `PKINIT_REALM`, `PKINIT_PRINCIPAL` | realm and client principal |
| `PKINIT_CA_CERT` | the test CA certificate |
| `PKINIT_KDC_SOCKET` | the UNIX socket the KDC listens on |
| `PKINIT_CLIENT_CERT`, `PKINIT_CLIENT_KEY` | the generated client certificate and key (file mode) |
| `PKINIT_CLIENT_IDENTITY`, `OPENSSL_CONF` | the token URI and the OpenSSL config that loads the pkcs11-provider (token mode) |
| `SETUP_PID` | PID of the `setup.py` process that owns the KDC |

The test directory is the parent of `$KRB5_CONFIG`
(`/tmp/pkinit-playground.XXXXXXXXXX/kdc`):

```
kdc/
├── krb5.conf  kdc.conf  acl  stash  db*  ccache
├── kdc.log               KDC log
├── kdc-trace.log         KDC-side trace (KDC plugin + libkrb5)
├── client-trace.log      client-side trace (kinit/klist in this shell)
├── openssl-pkcs11.cnf    token mode only
├── plugins/              preauth plugin directory used via plugin_base_dir
└── certs/
    ├── ca.pem  ca-key.pem
    ├── kdc.pem kdc-key.pem  kdc-chain.pem (TOFU: KDC cert + CA)
    ├── client.pem client-key.pem          (file mode)
    └── client-token.pem client-token-ca.pem (token mode)
```

Things to try:

```sh
# Authenticate with the generated client certificate (file mode)
kinit -X X509_user_identity=FILE:$PKINIT_CLIENT_CERT,$PKINIT_CLIENT_KEY \
      $PKINIT_PRINCIPAL@$PKINIT_REALM
klist

# Token mode: the identity is already in krb5.conf
kinit $PKINIT_PRINCIPAL@$PKINIT_REALM

# Anonymous PKINIT
kinit -n @$PKINIT_REALM

# See what the broker has pinned (TOFU mode); the summary prints the exact
# command with the right --socket
target/release/pkinit-trust-ctl --socket <work>/trust.sock list

# Turn the pin into a static anchor
target/release/pkinit-trust-ctl --socket <work>/trust.sock \
      export --anchors-dir /tmp/anchors

# Watch what the plugins do
tail -f $(dirname $KRB5_CONFIG)/client-trace.log
tail -f $(dirname $KRB5_CONFIG)/kdc-trace.log

# Inspect the certificates
openssl x509 -in $PKINIT_CA_CERT -noout -text
```

`kdestroy` and running `kinit` again only repeats the TOFU prompt once your
grant has expired; the broker remembers the decision in `trust.state.json`
for the life of the playground.

### Recipes

```sh
# Defaults: ECDSA P-256 certificates, ML-KEM-768, TOFU via the broker
./contrib/ci/local-ci.sh interactive

# Fully post-quantum: ML-DSA certificates and ML-KEM key exchange
./contrib/ci/local-ci.sh interactive --key-type mldsa65

# Stronger ML-KEM floor
./contrib/ci/local-ci.sh interactive --key-type mldsa87 --pqc-min-algorithm ML-KEM-1024

# Hybrid KEM
./contrib/ci/local-ci.sh interactive --pqc-min-algorithm ML-KEM-768-X25519

# Classic setup: RSA, DH/ECDH, static anchors, no broker
./contrib/ci/local-ci.sh interactive --no-tofu --key-type rsa:2048 --pqc-min-algorithm none

# Force the trust prompt onto kinit's own terminal, even in a desktop session
./contrib/ci/local-ci.sh interactive --ui tty

# Custom realm and principal
./contrib/ci/local-ci.sh interactive --realm EXAMPLE.TEST --principal alice

# Client identity from a PKCS#11 token
./contrib/ci/local-ci.sh interactive \
    --token "pkcs11:token=MyToken;object=mykey;type=private?pin-value=1234"
```

### Client identity on a PKCS#11 token

With `--token URI`, the playground doesn't generate a client certificate. It
uses a certificate already on a PKCS#11 token, and the private key never leaves
the token: at `kinit` time the client plugin signs through the OpenSSL
pkcs11-provider.

**Requirements**

- `python3-synta` and `python3-synta-krb5`, used to parse the certificate and
  its KRB5 SAN. The script checks for the krb5 subpackage explicitly.
- The OpenSSL pkcs11-provider (`pkcs11.so` under `ossl-modules/`).
- A reachable PKCS#11 module: the p11-kit proxy by default, or the one given
  with `--pkcs11-module`.
- On the token:
  - a private key, and a certificate under the same `object=` label,
  - a certificate whose SAN holds a KRB5 principal name (otherName
    `1.3.6.1.5.2.2`), unless you pass both `--realm` and `--principal`,
  - the certificate's issuing CA, either on the token or given with
    `--client-ca`. A self-signed certificate serves as its own anchor.

**The URI.** Use the form
`pkcs11:token=<label>;object=<key label>;type=private?pin-value=<PIN>`. It must
start with `pkcs11:`. The playground derives the certificate URI from it by
replacing `type=` with `type=cert`, and lists all the token's certificates
(dropping `object=` too) to find the issuer. The PIN in the query part is
omitted from everything the script prints, but it is written to `krb5.conf`
as `pkinit_identities = PKCS11:<URI>`. That file is inside the private
temporary work directory, which is deleted on exit.

**What changes compared with file mode**

- If `$OPENSSL_CONF` already points to a file, that file is used. Otherwise
  `openssl-pkcs11.cnf` is written, activating the default provider and the
  pkcs11-provider, with `pkcs11-module-path` set to the selected module.
- The certificate is extracted with `openssl storeutl` into
  `certs/client-token.pem`, and its issuer into `certs/client-token-ca.pem`.
- The KDC gets a second `pkinit_anchors` entry for that issuer, so it accepts
  a client certificate issued by a CA other than the playground's own.
- Unless given explicitly, realm and principal come from the certificate's
  KRB5 SAN.
- `pkinit_identities` is set in the realm's client stanza, so a plain
  `kinit $PKINIT_PRINCIPAL@$PKINIT_REALM` works.

The KDC's own certificates are still generated with `--key-type`. The token
certificate's algorithm is whatever is on the token.

### Troubleshooting

- **"KDC did not become ready"**: the script prints `kdc.log`. Check that
  the installed MIT krb5 is 1.22 or later: earlier releases cannot listen on
  a UNIX domain socket, so `krb5kdc` fails while setting up the network.
- **`kinit` fails after you deny or ignore the prompt**: that is expected.
  TOFU fails closed when you deny, when the prompt times out, or when the
  broker cannot be reached. Exit and start the playground again to begin with
  an empty trust store.
- **No prompt appears in a desktop session**: with `--ui auto` the broker
  prefers a desktop notification. If your notification daemon doesn't show
  action buttons, use `--ui tty`.
- **Token mode: "no certificate found"**: the token object named in the URI
  has no certificate. Import one under the same label, e.g. with
  `pkcs11-tool --login --write-object cert.der --type cert --label <label>`.
- **Token mode: "issuer not found on the token"**: import the CA certificate
  into the token or pass `--client-ca`.
- **Token mode: "synta.krb5 is a stub"**: install `python3-synta-krb5`.
- For anything else, read `client-trace.log` and `kdc-trace.log`. Both sides
  write traces from the kurbu5-pkinit plugin there.
