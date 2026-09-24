//! End-to-end PKINIT protocol exchange with the client identity's private
//! key held on a kryoptic PKCS#11 token.
//!
//! Provisions a fresh kryoptic SQLite token via `pkcs11-tool` and generates
//! keys that never leave the token: an EC P-256 key, and — when the
//! toolchain can create one — an ML-DSA-65 key.  Builds a PKINIT test PKI —
//! a software CA and KDC leaf, plus a CA-signed client certificate whose
//! SubjectPublicKeyInfo is the token key's public key and which carries the
//! PKINIT client SAN and the id-pkinit-KPClientAuth EKU — imports that
//! certificate onto the token, and loads the whole client identity from the
//! token through `PkinitIdentity::load(PKCS11:...)`.  The CA and KDC keys
//! match the client key's algorithm family, so the ML-DSA leg is a fully
//! post-quantum PKI.
//!
//! The full AS exchange (DH key exchange) then proves the token-backed
//! identity works end to end for each leg: the client signs the AuthPack
//! with the token key, the KDC verifies that signature against the token
//! certificate and its chain, and both sides derive the same session key.
//!
//! ## Debug details
//!
//! Every component emits `tracing` events so the run can be inspected at
//! any level of detail: each `pkcs11-tool` invocation, every certificate
//! (subject, issuer, key and signature algorithm, serial, validity,
//! extensions, SHA-256 fingerprint), the identity loaded back from the
//! token, and the exchange parameters and results (nonce, sizes, verified
//! signer, session key prefix).
//!
//! The subscriber honours `RUST_LOG`; with no filter set, only `warn` and
//! above is recorded, so a plain `cargo test` stays quiet.  To see the
//! details:
//!
//! ```bash
//! RUST_LOG=debug cargo test -p pkinit-core --test pkcs11_protocol -- --test-threads=1 --nocapture
//! ```
//!
//! The heavyweight token-state inspection (`pkcs11-tool -O` object dumps
//! after provisioning and each import) is deliberately kept at `trace`, so
//! it never appears in a plain `cargo test` or a `RUST_LOG=debug` run:
//! enable it explicitly (e.g. `RUST_LOG=trace`) when debugging token
//! provisioning.    When the same exchange runs inside the krb5 plugin, its
//! components report through the plugin's `krb5int_trace` bridge
//! (`kinit -d` / `KRB5_TRACE`); this test mirrors that observability via
//! `tracing` events.
//!
//! Requires kryoptic (`libkryoptic_pkcs11.so`), the OpenSSL pkcs11-provider
//! (`ossl-modules/pkcs11.so`), and `pkcs11-tool` (from opensc).  Skips
//! cleanly when any prerequisite is absent.
//!
//! Run with:
//! ```bash
//! cargo test -p pkinit-core --test pkcs11_protocol -- --test-threads=1 --nocapture
//! ```
//! `--test-threads=1` is required: `OPENSSL_CONF` is process-global, and the
//! kryoptic provider module binds to the first token configuration it sees.

use std::path::{Path, PathBuf};
use std::process::Command;

use pkinit_core::client::PkinitClientState;
use pkinit_core::config::{PkinitClientConfig, PkinitKdcConfig};
use pkinit_core::constants::{self, DhGroup};
use pkinit_core::crypto::kdf::OctetString2Key;
use pkinit_core::error::PkinitError;
use pkinit_core::identity::{IdentitySource, PkinitIdentity, TrustStore};
use pkinit_core::server::{BuildAsRepParams, PkinitKdcState};
use pkinit_core::test_support::{next_nonce, test_validity};
use synta::Integer;
use synta_certificate::crypto::{BackendPrivateKey, DataHasher, PrivateKey};
use synta_certificate::{
    Certificate, CertificateBuilder, ExtendedKeyUsageBuilder, Extensions, GeneralName,
    GeneralNames, NameBuilder, SubjectAlternativeNameBuilder, SubjectPublicKeyInfo, Time,
};

const PKCS11_TOOL: &str = "/usr/bin/pkcs11-tool";
/// Per-process token label so concurrent kryoptic test binaries (e.g. a
/// workspace `cargo test` running alongside `pkcs11_identity`) never collide
/// on the same token.
fn token_label() -> &'static str {
    static LABEL: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| format!("PkinitProto{}", std::process::id()));
    LABEL.as_str()
}
const KEY_LABEL: &str = "clientkey";
const KEY_ID_HEX: &str = "02";
/// PKCS#11 object (CKA_LABEL) of the token's ML-DSA-65 key.  The client
/// certificate imported for it carries the same label, so the identity
/// loader can derive the certificate URI from the key URI.
const MLDSA_KEY_OBJECT: &str = "mldsakey";
const MLDSA_KEY_ID_HEX: &str = "04";
const MLDSA_PARAM_SET: &str = "ML-DSA-65";
const SO_PIN: &str = "sopin12";
const USER_PIN: &str = "123456";

fn first_existing(cands: &[&str]) -> Option<String> {
    cands
        .iter()
        .find(|p| Path::new(p).exists())
        .map(|s| s.to_string())
}

fn kryoptic_lib() -> Option<String> {
    first_existing(&[
        "/usr/lib64/pkcs11/libkryoptic_pkcs11.so",
        "/usr/lib/x86_64-linux-gnu/pkcs11/libkryoptic_pkcs11.so",
        "/usr/lib/pkcs11/libkryoptic_pkcs11.so",
    ])
}

fn pkcs11_provider() -> Option<String> {
    first_existing(&[
        "/usr/lib64/ossl-modules/pkcs11.so",
        "/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so",
        "/usr/lib/ossl-modules/pkcs11.so",
    ])
}

// ── Debug details (RUST_LOG) ───────────────────────────────────────────────

/// Install the `tracing` subscriber used for the test's debug output.
///
/// Level filtering honours `RUST_LOG`; with no filter set, nothing below
/// `warn` is recorded, so a plain `cargo test` stays quiet.
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Emit a certificate's full structure at `debug` level: subject, issuer,
/// key and signature algorithm, serial, validity, each extension, and a
/// SHA-256 fingerprint of the DER.
fn dump_cert(label: &str, der: &[u8]) {
    let Ok(cert) = Certificate::from_der(der) else {
        tracing::debug!(label, "certificate: DER does not parse");
        return;
    };
    let tbs = &cert.tbs_certificate;
    let fingerprint = synta_certificate::default_data_hasher()
        .hash_data("sha256", der)
        .ok()
        .as_deref()
        .map(hex_lower)
        .unwrap_or_default();
    tracing::debug!(
        label,
        subject = %synta_certificate::format_dn(tbs.subject.as_bytes()),
        issuer = %synta_certificate::format_dn(tbs.issuer.as_bytes()),
        key_alg = %synta_certificate::identify_public_key_algorithm(
            &tbs.subject_public_key_info.algorithm.algorithm,
        )
        .unwrap_or("unknown"),
        sig_alg = %synta_certificate::identify_signature_algorithm(&tbs.signature.algorithm),
        serial = %hex_lower(tbs.serial_number.as_bytes()),
        not_before = ?tbs.validity.not_before,
        not_after = ?tbs.validity.not_after,
        der_len = der.len(),
        sha256 = %fingerprint,
        "certificate"
    );
    if let Some(raw) = &tbs.extensions {
        let Ok(exts) = Extensions::from_der(raw.as_bytes()) else {
            tracing::debug!(label, "certificate: extensions do not parse");
            return;
        };
        for ext in exts.iter() {
            let critical = ext.critical.map(bool::from).unwrap_or(false);
            tracing::debug!(
                label,
                ext = %synta_certificate::extension_oid_name(&ext.extn_id),
                critical,
                value_len = ext.extn_value.as_bytes().len(),
                "certificate extension"
            );
            if ext.extn_id.components() == synta_certificate::oids::SUBJECT_ALT_NAME {
                dump_san(label, ext.extn_value.as_bytes());
            }
        }
    }
}

/// Decode a Subject Alternative Name extension value and log each entry at
/// `debug` level; Kerberos SANs (id-pkinit-san) decode to the principal
/// string.
fn dump_san(label: &str, san_der: &[u8]) {
    let Ok(names) = GeneralNames::from_der(san_der) else {
        tracing::debug!(label, "SAN: does not parse");
        return;
    };
    for name in names.iter() {
        let desc = match name {
            GeneralName::OtherName(on) => match on
                .to_der()
                .ok()
                .and_then(|der| synta_krb5::principal::decode_krb5_san(&der))
            {
                Some(principal) => format!("Kerberos principal {principal}"),
                None => format!("otherName type-id={}", on.type_id),
            },
            GeneralName::Rfc822Name(s) => format!("rfc822Name {}", s.as_str()),
            GeneralName::DNSName(s) => format!("dNSName {}", s.as_str()),
            GeneralName::DirectoryName(n) => {
                format!(
                    "directoryName {}",
                    n.to_der()
                        .ok()
                        .map(|der| synta_certificate::format_dn(&der))
                        .unwrap_or_else(|| "<unparseable>".to_string())
                )
            }
            GeneralName::UniformResourceIdentifier(s) => {
                format!("uniformResourceIdentifier {}", s.as_str())
            }
            GeneralName::IPAddress(o) => format!("iPAddress {}", hex_lower(o.as_bytes())),
            GeneralName::RegisteredID(oid) => format!("registeredID {oid}"),
            GeneralName::X400Address(_) => "x400Address".to_string(),
            GeneralName::EdiPartyName(_) => "ediPartyName".to_string(),
        };
        tracing::debug!(label, name = %desc, "SAN entry");
    }
}

/// A provisioned kryoptic token (always an EC P-256 key; an ML-DSA-65 key
/// when that leg runs), with `OPENSSL_CONF` pointed at the
/// pkcs11-provider.  Restores `OPENSSL_CONF` on drop.
struct Fixture {
    _dir: tempfile::TempDir,
    kryoptic_conf: PathBuf,
    lib: String,
    prev_conf: Option<std::ffi::OsString>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // SAFETY: the test runs single-threaded (--test-threads=1).
        match &self.prev_conf {
            Some(v) => unsafe { std::env::set_var("OPENSSL_CONF", v) },
            None => unsafe { std::env::remove_var("OPENSSL_CONF") },
        }
    }
}

impl Fixture {
    fn setup() -> Option<Self> {
        let lib = kryoptic_lib()?;
        tracing::debug!(
            module = %lib,
            token = token_label(),
            "provisioning kryoptic token"
        );
        if pkcs11_provider().is_none() {
            eprintln!("[pkcs11_protocol] skipping: pkcs11-provider absent");
            return None;
        }
        if !Path::new(PKCS11_TOOL).exists() {
            eprintln!("[pkcs11_protocol] skipping: pkcs11-tool absent");
            return None;
        }

        let dir = tempfile::Builder::new()
            .prefix("pkinit-pkcs11-protocol")
            .tempdir()
            .ok()?;
        let base = dir.path();
        let kryoptic_conf = base.join("token.conf");
        let db_path = base.join("kryoptic.db");
        std::fs::write(
            &kryoptic_conf,
            format!(
                "[ec_point_encoding]\nencoding = \"Bytes\"\n[[slots]]\nslot = 1\ndescription = \"{}\"\ndbtype = \"sqlite\"\ndbargs = \"{}\"\n",
                token_label(),
                db_path.display()
            ),
        )
        .ok()?;
        tracing::trace!(
            path = %kryoptic_conf.display(),
            conf = %std::fs::read_to_string(&kryoptic_conf).unwrap_or_default(),
            "KRYOPTIC_CONF"
        );
        let conf_str = kryoptic_conf.to_string_lossy().into_owned();

        let run = |args: &[&str]| -> bool {
            let out = Command::new(PKCS11_TOOL)
                .args(args)
                .args(["--module", &lib])
                .env("KRYOPTIC_CONF", &conf_str)
                .output()
                .expect("pkcs11-tool");
            tracing::debug!(
                args = %args.join(" "),
                ok = out.status.success(),
                "pkcs11-tool"
            );
            tracing::trace!(
                args = %args.join(" "),
                stdout = %String::from_utf8_lossy(&out.stdout),
                stderr = %String::from_utf8_lossy(&out.stderr),
                "pkcs11-tool output"
            );
            if !out.status.success() {
                eprintln!(
                    "[pkcs11_protocol] {:?} stderr: {}",
                    args,
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            out.status.success()
        };

        if !run(&["--init-token", "--label", token_label(), "--so-pin", SO_PIN]) {
            return None;
        }
        if !run(&[
            "--init-pin",
            "--token-label",
            token_label(),
            "--so-pin",
            SO_PIN,
            "--pin",
            USER_PIN,
        ]) {
            return None;
        }
        if !run(&[
            "--keypairgen",
            "--key-type",
            "EC:prime256v1",
            "--label",
            KEY_LABEL,
            "--id",
            KEY_ID_HEX,
            "--usage-sign",
            "--token-label",
            token_label(),
            "--pin",
            USER_PIN,
        ]) {
            return None;
        }

        // Point OPENSSL_CONF at the pkcs11-provider (bound to this kryoptic
        // token) BEFORE any in-process OSSL_STORE access, so the provider
        // initialises against this fixture's configuration, not the
        // system-default one.
        let conf_path = base.join("openssl.cnf");
        let provider = pkcs11_provider().expect("checked above");
        std::fs::write(
            &conf_path,
            format!(
                "openssl_conf = openssl_init\n[openssl_init]\nproviders = provider_sect\n[provider_sect]\ndefault = default_sect\npkcs11 = pkcs11_sect\n[default_sect]\nactivate = 1\n[pkcs11_sect]\nmodule = {}\npkcs11-module-path = {}\npkcs11-module-init-args = kryoptic_conf={}\nactivate = 1\n",
                provider,
                lib,
                kryoptic_conf.display()
            ),
        )
        .ok()?;
        tracing::trace!(
            path = %conf_path.display(),
            conf = %std::fs::read_to_string(&conf_path).unwrap_or_default(),
            "OPENSSL_CONF (pkcs11-provider)"
        );
        let prev_conf = std::env::var_os("OPENSSL_CONF");
        // SAFETY: single-threaded test.
        unsafe { std::env::set_var("OPENSSL_CONF", &conf_path) };

        Some(Fixture {
            _dir: dir,
            kryoptic_conf,
            lib,
            prev_conf,
        })
    }

    fn key_uri(&self, object: &str) -> String {
        format!(
            "pkcs11:token={};object={};type=private?pin-value={}",
            token_label(),
            object,
            USER_PIN
        )
    }

    /// Import a certificate onto the token under `label`/`id` — the same
    /// values as the key object it pairs with, so the identity loader can
    /// derive the certificate URI from the key URI.
    fn import_cert(&self, cert_der: &[u8], label: &str, id_hex: &str) -> bool {
        let cert_path = self._dir.path().join(format!("client-{label}.der"));
        if std::fs::write(&cert_path, cert_der).is_err() {
            return false;
        }
        let conf_str = self.kryoptic_conf.to_string_lossy().into_owned();
        let out = Command::new(PKCS11_TOOL)
            .args([
                "--write-object",
                &cert_path.to_string_lossy(),
                "--type",
                "cert",
                "--label",
                label,
                "--id",
                id_hex,
                "--token-label",
                token_label(),
                "--login",
                "--pin",
                USER_PIN,
            ])
            .args(["--module", &self.lib])
            .env("KRYOPTIC_CONF", &conf_str)
            .output()
            .expect("write-object");
        tracing::debug!(
            label,
            id = id_hex,
            ok = out.status.success(),
            "import certificate onto token"
        );
        if !out.status.success() {
            eprintln!(
                "[pkcs11_protocol] write-object stderr: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        out.status.success()
    }

    /// Generate an ML-DSA-65 key inside the token via the OpenSSL `pkcs11`
    /// provider and return the `type=private` URI that selects it.
    ///
    /// The child `openssl` inherits `OPENSSL_CONF`, which the fixture points
    /// at the pkcs11-provider bound to this token.  `genpkey` exits
    /// non-zero even on success because it cannot serialize the
    /// non-exportable token key to stdout, so success is confirmed by the
    /// caller loading the key rather than by exit status.
    fn gen_mldsa_token_key(&self) -> Option<String> {
        let gen_uri = format!(
            "pkcs11:token={};object={};id=%{}?pin-value={}",
            token_label(),
            MLDSA_KEY_OBJECT,
            MLDSA_KEY_ID_HEX,
            USER_PIN
        );
        tracing::debug!(
            algorithm = MLDSA_PARAM_SET,
            key_uri = %gen_uri,
            "generating ML-DSA key inside token (openssl genpkey)"
        );
        let conf_str = self.kryoptic_conf.to_string_lossy().into_owned();
        let out = Command::new("openssl")
            .args([
                "genpkey",
                "-provider",
                "pkcs11",
                "-provider",
                "default",
                "-propquery",
                "?provider=pkcs11",
                "-algorithm",
                MLDSA_PARAM_SET,
                "-pkeyopt",
                &format!("pkcs11_uri:{gen_uri}"),
            ])
            .env("KRYOPTIC_CONF", &conf_str)
            .output()
            .ok()?;
        let _ = out;
        Some(format!(
            "pkcs11:token={};object={};type=private?pin-value={}",
            token_label(),
            MLDSA_KEY_OBJECT,
            USER_PIN
        ))
    }

    /// List the token's objects as `pkcs11-tool` sees them — what any
    /// PKCS#11 consumer (including the identity loader) can discover.
    ///
    /// This is a heavyweight call (it logs into the token and serializes
    /// every object), so it is only ever invoked from
    /// [`dump_token_state`], which keeps it behind the `trace` level.
    fn list_objects(&self) -> Option<String> {
        let args = [
            "-O",
            "--login",
            "--pin",
            USER_PIN,
            "--token-label",
            token_label(),
            "--module",
            &self.lib,
        ];
        let conf_str = self.kryoptic_conf.to_string_lossy().into_owned();
        let out = Command::new(PKCS11_TOOL)
            .args(args)
            .env("KRYOPTIC_CONF", &conf_str)
            .output()
            .ok()?;
        Some(format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

/// Emit the token's object listing at `trace`, tagged with `context` (e.g.
/// "after provisioning").   Deliberately off by default: a plain
/// `cargo test` (or a `RUST_LOG=debug` run) never surfaces it — enable it
/// explicitly (e.g. `RUST_LOG=trace`) when debugging token provisioning.
fn dump_token_state(fix: &Fixture, context: &str) {
    if let Some(listing) = fix.list_objects() {
        tracing::trace!(context, listing = %listing, "token objects");
    }
}

struct TestO2K;

impl OctetString2Key for TestO2K {
    fn random_to_key(
        &self,
        enctype: i32,
        random_data: &[u8],
    ) -> Result<native_ossl::util::SecretBuf, PkinitError> {
        let len = self.key_length(enctype)?;
        let mut key = random_data.to_vec();
        key.resize(len, 0);
        Ok(native_ossl::util::SecretBuf::new(key[..len].to_vec()))
    }

    fn random_length(&self, enctype: i32) -> Result<usize, PkinitError> {
        self.key_length(enctype)
    }

    fn key_length(&self, enctype: i32) -> Result<usize, PkinitError> {
        match enctype {
            17 => Ok(16),
            18 => Ok(32),
            _ => Err(PkinitError::Unsupported(format!("enctype {enctype}"))),
        }
    }
}

/// Algorithm family of the software-generated CA and KDC keys.  The client
/// key is always token-resident; only its public key appears in the client
/// certificate.
#[derive(Clone, Copy)]
enum TestKey {
    EcP256,
    MlDsa65,
}

impl TestKey {
    fn what(&self) -> &'static str {
        match self {
            Self::EcP256 => "EC P-256",
            Self::MlDsa65 => "ML-DSA-65",
        }
    }

    fn generate_software(&self) -> BackendPrivateKey {
        match self {
            Self::EcP256 => BackendPrivateKey::generate_ec("P-256"),
            Self::MlDsa65 => BackendPrivateKey::generate_ml_dsa(MLDSA_PARAM_SET),
        }
        .expect("generate software key")
    }
}

/// A test CA (software, `key`'s algorithm), a CA-signed KDC identity (same
/// algorithm), and a CA-signed client certificate whose SubjectPublicKeyInfo
/// is `client_spki` — the token key's public key.  The client private key is
/// generated inside the token and never exported; only its public half
/// appears in the certificate.  Returns `(client_cert_der, kdc_id,
/// trust_store)`.
fn build_test_pki(client_spki: &[u8], key: TestKey) -> (Vec<u8>, PkinitIdentity, TrustStore) {
    let ca_key = key.generate_software();
    let ca_pkcs8 = ca_key.to_der().unwrap();
    let ca_spki = ca_key.public_key_spki_der().unwrap();
    let ca_name = NameBuilder::new()
        .common_name("Test PKINIT CA")
        .build()
        .unwrap();

    let ca_backend = BackendPrivateKey::from_pkcs8_der_unchecked(ca_pkcs8);
    let ca_signer = PrivateKey::as_signer(&ca_backend, "sha256");

    let ca_ski = synta_certificate::encode_subject_key_identifier(
        &ca_spki,
        synta_certificate::KeyIdMethod::Rfc5280Sha1,
        &synta_certificate::OpensslKeyIdHasher,
    )
    .unwrap();
    let ca_aki = synta_certificate::encode_authority_key_identifier(
        &ca_spki,
        synta_certificate::KeyIdMethod::Rfc5280Sha1,
        &synta_certificate::OpensslKeyIdHasher,
    )
    .unwrap();
    let bc_der = synta_certificate::encode_basic_constraints(true, None).unwrap();

    let (nb, na) = test_validity().expect("validity window");
    let ca_cert_der = CertificateBuilder::new()
        .subject_name(&ca_name)
        .issuer_name(&ca_name)
        .public_key_der(&ca_spki)
        .serial_number(Integer::from_i64(1))
        .not_valid_before(Time::UtcTime(nb))
        .not_valid_after(Time::UtcTime(na))
        .add_extension_oid(
            synta_certificate::oids::SUBJECT_KEY_IDENTIFIER,
            false,
            &ca_ski,
        )
        .add_extension_oid(
            synta_certificate::oids::AUTHORITY_KEY_IDENTIFIER,
            false,
            &ca_aki,
        )
        .add_extension_oid(synta_certificate::oids::BASIC_CONSTRAINTS, true, &bc_der)
        .sign(&ca_signer)
        .unwrap();

    let leaf_name = |cn: &str| NameBuilder::new().common_name(cn).build().unwrap();
    let ku_der =
        synta_certificate::encode_key_usage(1 << synta_certificate::KEY_USAGE_DIGITAL_SIGNATURE)
            .unwrap();

    // ── Client certificate: CA-signed, SPKI is the token key's public key ──
    let client_name = leaf_name("Test Token Client");
    let client_san = synta_krb5::principal::encode_krb5_san("testuser", "EXAMPLE.COM").unwrap();
    let client_san_der = SubjectAlternativeNameBuilder::new()
        .other_name(&client_san)
        .build()
        .unwrap();
    let client_eku_der = ExtendedKeyUsageBuilder::new()
        .add_oid(constants::ID_PKINIT_KPCLIENT_AUTH)
        .build()
        .unwrap();
    let client_ski = synta_certificate::encode_subject_key_identifier(
        client_spki,
        synta_certificate::KeyIdMethod::Rfc5280Sha1,
        &synta_certificate::OpensslKeyIdHasher,
    )
    .unwrap();
    let client_aki = synta_certificate::encode_authority_key_identifier(
        &ca_spki,
        synta_certificate::KeyIdMethod::Rfc5280Sha1,
        &synta_certificate::OpensslKeyIdHasher,
    )
    .unwrap();

    let (nb, na) = test_validity().expect("validity window");
    let client_cert_der = CertificateBuilder::new()
        .subject_name(&client_name)
        .issuer_name(&ca_name)
        .public_key_der(client_spki)
        .serial_number(Integer::from_i64(2))
        .not_valid_before(Time::UtcTime(nb))
        .not_valid_after(Time::UtcTime(na))
        .add_extension_oid(
            synta_certificate::oids::SUBJECT_ALT_NAME,
            false,
            &client_san_der,
        )
        .add_extension_oid(
            synta_certificate::oids::EXTENDED_KEY_USAGE,
            false,
            &client_eku_der,
        )
        .add_extension_oid(synta_certificate::oids::KEY_USAGE, true, &ku_der)
        .add_extension_oid(
            synta_certificate::oids::SUBJECT_KEY_IDENTIFIER,
            false,
            &client_ski,
        )
        .add_extension_oid(
            synta_certificate::oids::AUTHORITY_KEY_IDENTIFIER,
            false,
            &client_aki,
        )
        .sign(&ca_signer)
        .unwrap();

    // ── KDC identity: software key of the same family as the CA ────────────
    let kdc_key = key.generate_software();
    let kdc_pkcs8 = kdc_key.to_der().unwrap();
    let kdc_spki = kdc_key.public_key_spki_der().unwrap();
    let kdc_name = leaf_name("Test KDC");
    let kdc_san =
        synta_krb5::principal::encode_krb5_san("krbtgt/EXAMPLE.COM", "EXAMPLE.COM").unwrap();
    let kdc_san_der = SubjectAlternativeNameBuilder::new()
        .other_name(&kdc_san)
        .build()
        .unwrap();
    let kdc_eku_der = ExtendedKeyUsageBuilder::new()
        .add_oid(constants::ID_PKINIT_KPKDC)
        .build()
        .unwrap();
    let kdc_ski = synta_certificate::encode_subject_key_identifier(
        &kdc_spki,
        synta_certificate::KeyIdMethod::Rfc5280Sha1,
        &synta_certificate::OpensslKeyIdHasher,
    )
    .unwrap();
    let kdc_aki = synta_certificate::encode_authority_key_identifier(
        &ca_spki,
        synta_certificate::KeyIdMethod::Rfc5280Sha1,
        &synta_certificate::OpensslKeyIdHasher,
    )
    .unwrap();

    let (nb, na) = test_validity().expect("validity window");
    let kdc_cert_der = CertificateBuilder::new()
        .subject_name(&kdc_name)
        .issuer_name(&ca_name)
        .public_key_der(&kdc_spki)
        .serial_number(Integer::from_i64(3))
        .not_valid_before(Time::UtcTime(nb))
        .not_valid_after(Time::UtcTime(na))
        .add_extension_oid(
            synta_certificate::oids::SUBJECT_ALT_NAME,
            false,
            &kdc_san_der,
        )
        .add_extension_oid(
            synta_certificate::oids::EXTENDED_KEY_USAGE,
            false,
            &kdc_eku_der,
        )
        .add_extension_oid(synta_certificate::oids::KEY_USAGE, true, &ku_der)
        .add_extension_oid(
            synta_certificate::oids::SUBJECT_KEY_IDENTIFIER,
            false,
            &kdc_ski,
        )
        .add_extension_oid(
            synta_certificate::oids::AUTHORITY_KEY_IDENTIFIER,
            false,
            &kdc_aki,
        )
        .sign(&ca_signer)
        .unwrap();

    let kdc_id = PkinitIdentity {
        cert_der: kdc_cert_der,
        signing_key: Some(BackendPrivateKey::from_pkcs8_der_unchecked(kdc_pkcs8)),
        chain: vec![ca_cert_der.clone()],
    };

    let mut trust_store = TrustStore::new();
    trust_store.add_anchor(ca_cert_der);

    (client_cert_der, kdc_id, trust_store)
}

#[test]
fn pkinit_as_exchange_with_token_backed_identity() {
    init_tracing();
    let Some(fix) = Fixture::setup() else {
        return;
    };
    dump_token_state(&fix, "after provisioning");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // ── EC P-256 leg ──
        run_exchange(&fix, KEY_LABEL, KEY_ID_HEX, TestKey::EcP256);

        // ── ML-DSA-65 leg: a fully post-quantum PKI (ML-DSA-65 CA and KDC
        // alongside the ML-DSA-65 token client key), so ML-DSA is exercised
        // on both sides of the exchange.  Skipped when this toolchain cannot
        // generate or use a token ML-DSA key — the affected sub-check is
        // skipped rather than failing the suite.
        let Some(mldsa_uri) = fix.gen_mldsa_token_key() else {
            eprintln!("[pkcs11_protocol] skipping ML-DSA leg: `openssl` binary not available");
            return;
        };
        dump_token_state(&fix, "after ML-DSA keygen");
        match BackendPrivateKey::from_pkcs11_uri(&mldsa_uri) {
            Ok(_) => run_exchange(&fix, MLDSA_KEY_OBJECT, MLDSA_KEY_ID_HEX, TestKey::MlDsa65),
            Err(e) => {
                eprintln!(
                    "[pkcs11_protocol] skipping ML-DSA leg: token ML-DSA key not usable: {e}"
                );
            }
        }
    }));

    // `fix` drops here, restoring OPENSSL_CONF even if the assertions panicked.
    result.expect("pkinit_as_exchange_with_token_backed_identity panicked");
}

/// Full PKINIT AS exchange using a token-resident client key: load the key
/// (`object`) through the PKCS#11 URI, build the test PKI around its SPKI
/// with CA/KDC keys of the `pki_key` family, import the resulting client
/// certificate onto the token, load the whole identity back from the token,
/// and drive the exchange.
fn run_exchange(fix: &Fixture, object: &str, id_hex: &str, pki_key: TestKey) {
    tracing::debug!(
        object,
        id = id_hex,
        key_alg = pki_key.what(),
        "starting leg"
    );
    let key_uri = fix.key_uri(object);
    tracing::debug!(key_uri = %key_uri, "loading token key");

    // First in-process OSSL_STORE access: the token key (its SPKI is
    // needed to build the client certificate).
    let key = BackendPrivateKey::from_pkcs11_uri(&key_uri)
        .unwrap_or_else(|e| panic!("load token key from PKCS#11 URI: {e}"));
    let spki = key
        .public_key_spki_der()
        .expect("token key public_key_spki_der");
    if let Ok(spki_info) = SubjectPublicKeyInfo::from_der(&spki) {
        tracing::debug!(
            key_alg = %synta_certificate::identify_public_key_algorithm(
                &spki_info.algorithm.algorithm,
            )
            .unwrap_or("unknown"),
            spki_len = spki.len(),
            "token key SPKI"
        );
    }

    let (client_cert_der, kdc_id, trust_store) = build_test_pki(&spki, pki_key);
    dump_cert("CA (trust anchor)", &kdc_id.chain[0]);
    dump_cert("KDC identity", &kdc_id.cert_der);
    dump_cert("client (built)", &client_cert_der);

    assert!(
        fix.import_cert(&client_cert_der, object, id_hex),
        "importing client cert onto token failed"
    );
    dump_token_state(fix, &format!("after importing {object} cert"));

    // Load the whole client identity from the token.
    let src = IdentitySource::parse(&format!("PKCS11:{key_uri}")).expect("parse identity");
    let client_id = PkinitIdentity::load(&src).expect("load PKCS#11 identity");
    dump_cert("client (loaded from token)", &client_id.cert_der);
    tracing::debug!(
        chain_len = client_id.chain.len(),
        has_signing_key = client_id.signing_key.is_some(),
        "identity loaded from token"
    );
    assert_eq!(
        client_id.cert_der, client_cert_der,
        "loaded cert DER must be the cert imported onto the token"
    );
    assert!(
        client_id.signing_key.is_some(),
        "a PKCS#11 identity must carry a token-backed signing key"
    );
    assert!(client_id.chain.is_empty(), "no chain certs were imported");

    // ── Full AS exchange: the client's AuthPack is signed by the token ──
    let o2k = TestO2K;
    let client_config = PkinitClientConfig {
        dh_group: DhGroup::EcP256,
        ..Default::default()
    };
    let req_body_der = b"token-client-req-body";
    let nonce = next_nonce();
    let enctype = 18;
    let ctime = 1719600000i64;
    tracing::debug!(
        dh_group = ?client_config.dh_group,
        nonce,
        enctype,
        ctime,
        "AS exchange parameters"
    );
    let mut client = PkinitClientState::new(client_id, trust_store.clone(), client_config);
    client.set_kdc_identity("krbtgt/EXAMPLE.COM@EXAMPLE.COM".to_string(), None);

    let server = PkinitKdcState::new(kdc_id, trust_store, PkinitKdcConfig::default()).unwrap();

    let pa_req = client
        .build_as_req(nonce, ctime, 0, req_body_der)
        .unwrap_or_else(|e| panic!("client builds AS-REQ ({}): {e}", pki_key.what()));
    tracing::debug!(
        pa_req_len = pa_req.len(),
        "AS-REQ built (AuthPack signed by token)"
    );

    // The KDC verifies the AuthPack signature against the token
    // certificate and rejects it if the key does not match.
    let verified = server
        .verify_as_req(&pa_req, Some(req_body_der), 300, ctime)
        .unwrap_or_else(|e| {
            panic!(
                "KDC verifies AuthPack signed with the token key ({}): {e}",
                pki_key.what()
            )
        });
    assert!(!verified.is_anonymous);
    tracing::debug!(
        is_anonymous = verified.is_anonymous,
        "KDC verified AuthPack"
    );

    let as_req_full = b"token-client-full-as-req";
    let client_name = "testuser@EXAMPLE.COM";
    let server_name = "krbtgt/EXAMPLE.COM@EXAMPLE.COM";
    let (pa_rep, server_key) = server
        .build_as_rep(
            &verified,
            &BuildAsRepParams {
                nonce,
                enctype,
                as_req_der: as_req_full,
                client_name,
                server_name,
            },
            &o2k,
        )
        .expect("KDC builds AS-REP");
    tracing::debug!(pa_rep_len = pa_rep.len(), "AS-REP built");

    let client_key = client
        .process_as_rep(
            &pa_rep,
            &pkinit_core::client::AsRepParams {
                nonce,
                enctype,
                as_req_der: as_req_full,
                pa_rep_raw: &pa_rep,
                client_name,
                server_name,
            },
            &o2k,
        )
        .expect("client processes AS-REP");

    assert_eq!(client_key.enctype, server_key.enctype);
    assert_eq!(client_key.key_data.as_ref(), server_key.key_data.as_ref());
    assert_eq!(client_key.enctype, enctype);
    assert!(!client_key.key_data.as_ref().is_empty());
    let key_data = client_key.key_data.as_ref();
    tracing::debug!(
        enctype = client_key.enctype,
        key_len = key_data.len(),
        key_prefix = %hex_lower(&key_data[..key_data.len().min(8)]),
        "session key agreed"
    );

    eprintln!(
        "[pkcs11_protocol] PKINIT AS exchange OK ({}): AuthPack signed by kryoptic token key, session key agreed",
        pki_key.what()
    );
}
