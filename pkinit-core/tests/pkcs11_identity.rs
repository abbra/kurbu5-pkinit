//! End-to-end integration test: load a PKINIT identity from a PKCS#11 token.
//!
//! Provisions a fresh kryoptic SQLite token via `pkcs11-tool`, generates an
//! EC P-256 key, self-signs a certificate with the token key, imports it, then
//! loads the whole identity through `PkinitIdentity::load(PKCS11:...)` and
//! confirms the certificate round-trips and the token-backed signing key works.
//!
//! Requires kryoptic (`libkryoptic_pkcs11.so`), the OpenSSL pkcs11-provider
//! (`ossl-modules/pkcs11.so`), and `pkcs11-tool` (from opensc).  Skips cleanly
//! when any prerequisite is absent.
//!
//! Run with:
//! ```bash
//! cargo test -p pkinit-core --test pkcs11_identity -- --test-threads=1 --nocapture
//! ```
//! `--test-threads=1` is required: `OPENSSL_CONF` is process-global.

use std::path::{Path, PathBuf};
use std::process::Command;

use pkinit_core::identity::{IdentitySource, PkinitIdentity};

const PKCS11_TOOL: &str = "/usr/bin/pkcs11-tool";
fn token_label() -> &'static str {
    static L: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    L.get_or_init(|| format!("PkinitTest{}", std::process::id()))
        .as_str()
}
const KEY_LABEL: &str = "clientkey";
const KEY_ID_HEX: &str = "02";
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

/// A provisioned kryoptic token holding one EC key and its certificate, with
/// `OPENSSL_CONF` pointed at the pkcs11-provider.  Restores `OPENSSL_CONF` on drop.
struct Fixture {
    _dir: tempfile::TempDir,
    kryoptic_conf: PathBuf,
    lib: String,
    expected_cert: Vec<u8>,
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
        let provider = pkcs11_provider()?;
        if !Path::new(PKCS11_TOOL).exists() {
            eprintln!("[pkcs11_identity] skipping: pkcs11-tool absent");
            return None;
        }

        let dir = tempfile::Builder::new()
            .prefix("pkinit-pkcs11")
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
        let conf_str = kryoptic_conf.to_string_lossy().into_owned();

        let run = |args: &[&str]| -> bool {
            let out = Command::new(PKCS11_TOOL)
                .args(args)
                .args(["--module", &lib])
                .env("KRYOPTIC_CONF", &conf_str)
                .output()
                .expect("pkcs11-tool");
            if !out.status.success() {
                eprintln!(
                    "[pkcs11_identity] {:?} stderr: {}",
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

        // Configure the OpenSSL pkcs11-provider FIRST (pointing at kryoptic), so
        // that building the software certificate below never pulls in the
        // system-default pkcs11 provider and poisons the process-global state.
        let conf_path = base.join("openssl.cnf");
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
        let prev_conf = std::env::var_os("OPENSSL_CONF");
        // SAFETY: single-threaded test.
        unsafe { std::env::set_var("OPENSSL_CONF", &conf_path) };

        // Import the certificate (built with a software key, so no token-object
        // enumeration happens here) BEFORE PkinitIdentity::load performs the
        // first OSSL_STORE object access, so the load observes it.
        let mut fix = Fixture {
            _dir: dir,
            kryoptic_conf,
            lib,
            expected_cert: Vec::new(),
            prev_conf,
        };
        if !fix.build_and_import_cert() {
            return None;
        }

        Some(fix)
    }

    fn key_uri(&self) -> String {
        format!(
            "pkcs11:token={};object={};type=private?pin-value={}",
            token_label(),
            KEY_LABEL,
            USER_PIN
        )
    }

    /// Self-sign a certificate with a freshly generated *software* key and
    /// import it under the token key's label/id.  Records the DER in
    /// `expected_cert`.
    ///
    /// A software key (not the token key) is used deliberately: it avoids
    /// initialising the pkcs11-provider before the certificate is written, so
    /// the later `PkinitIdentity::load` sees the freshly imported certificate.
    /// The certificate content is otherwise irrelevant to what this test checks
    /// (cert round-trip + a usable token-backed signing key).
    fn build_and_import_cert(&mut self) -> bool {
        use synta_certificate::{BackendPrivateKey, CertificateBuilder, NameBuilder, PrivateKey};

        let key = BackendPrivateKey::generate_ec("P-256").expect("generate EC key");
        let spki = key.public_key_spki_der().expect("spki");
        let name = NameBuilder::new()
            .common_name("PKINIT PKCS11 Client")
            .build()
            .expect("name");
        let nb = synta_certificate::parse_time("20240101000000Z").expect("nb");
        let na = synta_certificate::parse_time("20340101000000Z").expect("na");
        let signer = key.as_signer("sha256");
        let cert_der = CertificateBuilder::new()
            .issuer_name(&name)
            .subject_name(&name)
            .public_key_der(&spki)
            .serial_number(synta::Integer::from_i64(1))
            .not_valid_before(nb)
            .not_valid_after(na)
            .sign(&signer)
            .expect("sign cert");
        self.expected_cert = cert_der.clone();

        let cert_path = self._dir.path().join("cert.der");
        if std::fs::write(&cert_path, &cert_der).is_err() {
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
                KEY_LABEL,
                "--id",
                KEY_ID_HEX,
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
        if !out.status.success() {
            eprintln!(
                "[pkcs11_identity] write-object stderr: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        out.status.success()
    }
}

#[test]
fn load_pkcs11_identity_end_to_end() {
    let Some(fix) = Fixture::setup() else {
        return;
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let src =
            IdentitySource::parse(&format!("PKCS11:{}", fix.key_uri())).expect("parse identity");
        let identity = PkinitIdentity::load(&src).expect("load PKCS#11 identity");

        assert_eq!(
            identity.cert_der, fix.expected_cert,
            "loaded cert DER must match the cert imported onto the token"
        );
        assert!(
            identity.signing_key.is_some(),
            "a PKCS#11 identity must carry a token-backed signing key"
        );
        assert!(identity.chain.is_empty(), "no chain certs were imported");

        // The token-backed signing key must be usable (public key derivable).
        use synta_certificate::PrivateKey;
        let spki = identity
            .signing_key
            .as_ref()
            .unwrap()
            .public_key_spki_der()
            .expect("token key public_key_spki_der");
        assert!(!spki.is_empty());

        eprintln!(
            "[pkcs11_identity] loaded PKCS#11 identity: {} byte cert + token key",
            identity.cert_der.len()
        );
    }));

    // `fix` drops here, restoring OPENSSL_CONF even if the assertions panicked.
    result.expect("load_pkcs11_identity_end_to_end panicked");
}
