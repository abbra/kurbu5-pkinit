#!/usr/bin/env python3
"""Ephemeral Kerberos realm with PKINIT for system integration tests.

Adapted from ahdapa's contrib/demo/ccache/setup.py.  Extends the base
Realm pattern with PKINIT PKI generation (CA + KDC cert + client cert),
krb5/kdc config with PKINIT stanzas, and per-interface plugin selection
for cross-testing between kurbu5-pkinit and MIT's built-in pkinit.

Usage:
    # Both sides use the same plugin:
    python3 setup.py --plugin-so /path/to/libkurbu5_pkinit.so

    # Mix KDC and client plugins:
    python3 setup.py --kdc-plugin-so /path/to/libkurbu5_pkinit.so \
                     --client-plugin-so /usr/lib64/krb5/plugins/preauth/pkinit.so
"""

import atexit
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time

REALM = "PKINIT.TEST"

# Key exchange: post-quantum (ML-KEM) by default, whatever the certificate
# algorithm. CLASSIC_KEX ("none") selects classic DH/ECDH instead, which only
# interop tests against MIT's own pkinit.so need, since it has no KEM support.
DEFAULT_PQC_MIN_ALGORITHM = "ML-KEM-768"
CLASSIC_KEX = "none"

# Composite (hybrid) KEMs are explicit opt-in on the KDC: a composite
# pkinit_pqc_min_algorithm only sets the pure ML-KEM floor there, so the KDC
# must also list the algorithm in pkinit_pqc_composite_algorithms.
COMPOSITE_KEM_ALGORITHMS = (
    "ML-KEM-768-X25519",
    "ML-KEM-768-ECDH-P256",
    "ML-KEM-1024-ECDH-P384",
)

# The KDC listens on a UNIX domain socket (MIT krb5 1.22+) rather than a TCP/UDP
# port, so any number of test realms can run side by side without port
# allocation. sun_path holds 108 bytes including the terminating NUL.
UNIX_PATH_MAX = 107


SUPPORTED_KEY_TYPES = {
    "ec:P-256": ("ec", "ec_paramgen_curve:P-256"),
    "ec:P-384": ("ec", "ec_paramgen_curve:P-384"),
    "ec:P-521": ("ec", "ec_paramgen_curve:P-521"),
    "rsa:2048": ("rsa", "rsa_keygen_bits:2048"),
    "rsa:3072": ("rsa", "rsa_keygen_bits:3072"),
    "rsa:4096": ("rsa", "rsa_keygen_bits:4096"),
    "mldsa44": ("mldsa44", None),
    "mldsa65": ("mldsa65", None),
    "mldsa87": ("mldsa87", None),
}

# Ticket encryption types the KDC supports and issues principal keys with
# (unrelated to --key-type, which is the PKINIT certificate algorithm):
# SHA-2 based AES (RFC 8009) rather than the older SHA-1 based AES (RFC
# 3962). This is deliberately KDC-side only (supported_enctypes) -- forcing
# the client's own enctype preference (e.g. via permitted_enctypes) is
# explicitly discouraged by krb5.conf(5) ("do not use unless required...")
# and empirically broke the anonymous/FAST-armored PKINIT exchange used by
# TOFU here, so the negotiated session key enctype is left to the library's
# own default negotiation.
ENCTYPES = ("aes256-cts-hmac-sha384-192", "aes128-cts-hmac-sha256-128")

# OID of the Kerberos PKINIT otherName SAN (RFC 4556 §3.2.2).
KRB5_SAN_OID = "1.3.6.1.5.2.2"

# OpenSSL pkcs11-provider and PKCS#11 module candidates (token mode);
# mirrors the discovery paths in pkinit-core.
PKCS11_PROVIDER_PATHS = (
    "/usr/lib64/ossl-modules/pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so",
    "/usr/lib/aarch64-linux-gnu/ossl-modules/pkcs11.so",
    "/usr/lib/powerpc64le-linux-gnu/ossl-modules/pkcs11.so",
    "/usr/lib/s390x-linux-gnu/ossl-modules/pkcs11.so",
    "/usr/lib/ossl-modules/pkcs11.so",
)
PKCS11_MODULE_PATHS = (
    "/usr/lib64/pkcs11/p11-kit-proxy.so",
    "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-proxy.so",
    "/usr/lib/aarch64-linux-gnu/pkcs11/p11-kit-proxy.so",
    "/usr/lib/powerpc64le-linux-gnu/pkcs11/p11-kit-proxy.so",
    "/usr/lib/s390x-linux-gnu/pkcs11/p11-kit-proxy.so",
    "/usr/lib/pkcs11/p11-kit-proxy.so",
)


def _short_tempdir(prefix):
    """Create a private temporary directory whose path leaves room for a
    socket name within sun_path: $TMPDIR when it is short enough, else /tmp."""
    base = tempfile.gettempdir()
    if len(os.fsencode(base)) > 64:
        base = "/tmp"
    return tempfile.mkdtemp(prefix=prefix, dir=base)


def first_existing(paths):
    for p in paths:
        if os.path.isfile(p):
            return p
    return None


def redact_pkcs11_uri(uri):
    """Strip the query component (may carry pin-value) for user-facing output."""
    return uri.split("?", 1)[0]


def pkcs11_cert_uri(uri):
    """Derive the certificate-selecting PKCS#11 URI from an identity URI.

    Mirrors pkinit-core identity/loader.rs ``pkcs11_cert_uri``: strip any
    ``type=`` path attribute, append ``type=cert``, preserve all other path
    attributes and the query component (carries ``pin-value``).
    """
    path, sep, query = uri.partition("?")
    components = [c for c in path.split(";") if not c.startswith("type=")]
    out = ";".join(components) + ";type=cert"
    if sep:
        out += "?" + query
    return out


def pkcs11_token_cert_uri(uri):
    """All-certificates URI for the token: drop ``object=`` as well, keep the
    rest of the path attributes and the query component."""
    path, sep, query = uri.partition("?")
    components = [
        c for c in path.split(";")
        if not c.startswith(("type=", "object="))
    ]
    out = ";".join(components) + ";type=cert"
    if sep:
        out += "?" + query
    return out


def _synta():
    """Import the python3-synta modules used for token-mode certificate work.

    Raises an actionable error when the packages (or the krb5 subpackage)
    are missing.  The check is a live decode, not just an import, because a
    python3-synta without python3-synta-krb5 loads a silent stub module.
    """
    try:
        import synta
        import synta.general_name as gn
        from synta.krb5 import Krb5PrincipalName
    except ImportError as e:
        raise RuntimeError(
            "token mode requires the python3-synta packages: "
            "dnf install python3-synta python3-synta-krb5"
        ) from e
    probe = Krb5PrincipalName(realm="R", name_type=1, components=["c"])
    if probe.realm != "R":
        raise RuntimeError(
            "python3-synta-krb5 is not installed (synta.krb5 is a stub): "
            "dnf install python3-synta-krb5"
        )
    return synta, gn, Krb5PrincipalName


def parse_krb5_san(cert_der):
    """Return ``(principal, realm)`` from the KRB5 otherName SAN of a DER
    certificate, or ``None`` when absent.

    Decodes with ``synta.krb5.Krb5PrincipalName`` -- the same decoder the
    kurbu5-pkinit plugin uses, so a SAN readable here is readable there.
    """
    synta, gn, Krb5PrincipalName = _synta()
    cert = synta.Certificate.from_der(cert_der)
    for name in cert.subject_alt_names():
        if isinstance(name, gn.OtherName) and str(name.type_id) == KRB5_SAN_OID:
            kp = Krb5PrincipalName.from_der(name.value)
            return "/".join(kp.components), kp.realm
    return None


def select_cert_anchor(leaf_der, candidate_ders):
    """Return the DER of the anchor for ``leaf_der`` among ``candidate_ders``.

    Self-signed leaf: the leaf itself.  Otherwise the first candidate whose
    subject matches the leaf's issuer and cryptographically verifies it.
    ``None`` when no anchor is found.
    """
    synta, _gn, _kp = _synta()
    leaf = synta.Certificate.from_der(leaf_der)
    if leaf.issuer == leaf.subject:
        return leaf_der
    for cand in candidate_ders:
        issuer = synta.Certificate.from_der(cand)
        if issuer.subject != leaf.issuer:
            continue
        try:
            leaf.verify_issued_by(issuer)
        except Exception:
            continue
        return cand
    return None


def _pem_blocks(text):
    """Split openssl storeutl output into individual PEM certificate blocks."""
    blocks, current = [], None
    for line in text.splitlines():
        s = line.strip()
        if s == "-----BEGIN CERTIFICATE-----":
            current = [s]
        elif s == "-----END CERTIFICATE-----":
            if current is not None:
                current.append(s)
                blocks.append("\n".join(current))
                current = None
        elif current is not None:
            current.append(s)
    return blocks


def _certs_from_file(path):
    """Parse a PEM file (one or more certificates) into Certificate objects."""
    synta, _gn, _kp = _synta()
    with open(path, "rb") as f:
        parsed = synta.Certificate.from_pem(f.read())
    if isinstance(parsed, list):
        return parsed
    return [parsed]


class PkinitRealm:
    def __init__(self, testdir=None, realm=None, kdc_socket=None,
                 kdc_plugin_so=None, client_plugin_so=None, principal=None,
                 key_type="ec:P-256",
                 pqc_min_algorithm=DEFAULT_PQC_MIN_ALGORITHM,
                 tofu_broker=None, client_token=None, client_ca=None,
                 pkcs11_module=None, krb5_prefix=None):
        # realm/principal are None by default so token mode can override them
        # with values derived from the token certificate's KRB5 SAN before
        # any config is written.
        self.realm = realm if realm is not None else REALM
        # An alternative MIT krb5 installation (e.g. a build carrying the
        # draft-bokovoy-kitten-pkinit-pqc pkinit.so) whose KDC, admin tools,
        # kinit, libraries and KDB/preauth plugins replace the system ones.
        self.krb5_prefix = os.path.abspath(krb5_prefix) if krb5_prefix else None
        self.principal = principal if principal is not None else "user"
        self.key_type = key_type
        # None or CLASSIC_KEX: classic DH/ECDH, no pkinit_pqc_min_algorithm.
        if pqc_min_algorithm == CLASSIC_KEX:
            pqc_min_algorithm = None
        self.pqc_min_algorithm = pqc_min_algorithm
        # When set, the client krb5.conf enables trust-on-first-use of the KDC
        # CA via the broker at this socket path, omits the client's KDC-CA
        # anchor (so local validation fails and the broker path engages), and
        # turns on auto_fast_armor so the anonymous exchange establishes trust.
        self.tofu_broker = tofu_broker
        # Token mode: the client identity is a certificate on a PKCS#11 token
        # (loaded at runtime by the plugin via the OpenSSL pkcs11-provider);
        # no client key material is ever generated or extracted.
        self.client_token = client_token
        self.client_ca = client_ca
        self.pkcs11_module = pkcs11_module
        self.token_principal = None
        self.token_realm = None
        if client_token:
            if not client_token.startswith("pkcs11:"):
                raise ValueError(
                    f"--client-token must be a pkcs11: URI, got {client_token!r}"
                )
            if client_ca and not os.path.isfile(client_ca):
                raise ValueError(f"--client-ca file not found: {client_ca}")
        elif client_ca:
            raise ValueError("--client-ca requires --client-token")
        if key_type not in SUPPORTED_KEY_TYPES:
            raise ValueError(
                f"Unsupported key type: {key_type}. "
                f"Supported: {', '.join(sorted(SUPPORTED_KEY_TYPES))}"
            )
        self.testdir = os.path.abspath(
            testdir or tempfile.mkdtemp(prefix="pkinit-test-")
        )
        self.kdc_plugin_so = os.path.abspath(kdc_plugin_so) if kdc_plugin_so else None
        self.client_plugin_so = os.path.abspath(client_plugin_so) if client_plugin_so else None
        self._kdc_proc = None

        self.krb5_conf = os.path.join(self.testdir, "krb5.conf")
        self.kdc_conf = os.path.join(self.testdir, "kdc.conf")
        self.kdc_log = os.path.join(self.testdir, "kdc.log")
        self.kdc_trace = os.path.join(self.testdir, "kdc-trace.log")
        self.client_trace = os.path.join(self.testdir, "client-trace.log")
        self.db_path = os.path.join(self.testdir, "db")
        self.acl_file = os.path.join(self.testdir, "acl")
        self.stash = os.path.join(self.testdir, "stash")
        self.ccache = os.path.join(self.testdir, "ccache")

        self.certs_dir = os.path.join(self.testdir, "certs")
        self.plugins_dir = os.path.join(self.testdir, "plugins")

        self.openssl_conf = os.path.join(self.testdir, "openssl-pkcs11.cnf")
        self.client_token_leaf = os.path.join(self.certs_dir, "client-token.pem")
        self.client_token_anchor = os.path.join(self.certs_dir, "client-token-ca.pem")

        self.ca_cert = os.path.join(self.certs_dir, "ca.pem")
        self.ca_key = os.path.join(self.certs_dir, "ca-key.pem")
        self.kdc_cert = os.path.join(self.certs_dir, "kdc.pem")
        self.kdc_key = os.path.join(self.certs_dir, "kdc-key.pem")
        self.client_cert = os.path.join(self.certs_dir, "client.pem")
        self.client_key = os.path.join(self.certs_dir, "client-key.pem")

        os.makedirs(self.testdir, exist_ok=True)

        # KDC socket: an explicit path, or kdc.sock in a fresh private
        # directory under the temp dir (kept short for sun_path; testdir may
        # be arbitrarily deep). The directory is removed by stop(), or at exit
        # if the KDC never started.
        self._kdc_socket_dir = None
        if kdc_socket is None:
            self._kdc_socket_dir = _short_tempdir("pkinit-kdc-")
            atexit.register(shutil.rmtree, self._kdc_socket_dir, True)
            kdc_socket = os.path.join(self._kdc_socket_dir, "kdc.sock")
        self.kdc_socket = os.path.abspath(kdc_socket)
        if len(os.fsencode(self.kdc_socket)) > UNIX_PATH_MAX:
            raise ValueError(
                f"KDC socket path is too long for a UNIX domain socket "
                f"({len(os.fsencode(self.kdc_socket))} > {UNIX_PATH_MAX} bytes): "
                f"{self.kdc_socket}"
            )

    @property
    def env(self):
        e = os.environ.copy()
        e["KRB5_CONFIG"] = self.krb5_conf
        e["KRB5_KDC_PROFILE"] = self.kdc_conf
        e["KRB5CCNAME"] = f"FILE:{self.ccache}"
        e["KRB5RCACHEDIR"] = self.testdir
        # KDC-side trace only: surfaces pkinit_trace!() output from
        # kdc_plugin.rs plus MIT krb5's own internal KDC preauth trace
        # messages. This `env` property is used to launch the krb5kdc
        # process (and kdb5_util/kadmin.local) -- kinit/klist invocations
        # get their own KRB5_TRACE (self.client_trace) via the env-file
        # written by main(), so KDC and client traces never land in the
        # same file and interleave.
        e["KRB5_TRACE"] = self.kdc_trace
        e.update(self.prefix_env())
        return e

    def prefix_env(self):
        """PATH / LD_LIBRARY_PATH selecting the --krb5-prefix installation
        (empty without one). Also exported via the env-file, so kinit/klist
        run from that installation too."""
        if not self.krb5_prefix:
            return {}
        p = self.krb5_prefix
        path = os.environ.get("PATH", "")
        libs = os.environ.get("LD_LIBRARY_PATH", "")
        return {
            "PATH": f"{p}/sbin:{p}/bin" + (f":{path}" if path else ""),
            "LD_LIBRARY_PATH": f"{p}/lib" + (f":{libs}" if libs else ""),
        }

    def _plugin_dir_candidates(self, kind, system_dirs):
        """The --krb5-prefix plugin directory first, then the system ones."""
        if self.krb5_prefix:
            return [os.path.join(self.krb5_prefix, "lib", "krb5", "plugins", kind)]
        return system_dirs

    # -- Client token identity (token mode) --

    def load_client_token_identity(self):
        """Prepare the client identity held on a PKCS#11 token.

        Writes an OpenSSL pkcs11-provider config into testdir (reusing
        ``$OPENSSL_CONF`` when it already points at an existing file),
        extracts the certificate bound to the key object from the token via
        ``openssl storeutl``, derives the KRB5 principal and realm from the
        certificate's KRB5 otherName SAN, and resolves the issuer anchor:
        the ``--client-ca`` file when given, otherwise a certificate on the
        token that issued the leaf.

        Idempotent: re-running re-extracts and rewrites the local files.
        """
        if not self.client_token:
            return
        os.makedirs(self.certs_dir, exist_ok=True)

        # Provider config: reuse the caller's OPENSSL_CONF when it exists.
        existing = os.environ.get("OPENSSL_CONF")
        if existing and os.path.isfile(existing):
            self.openssl_conf = existing
        else:
            provider = first_existing(PKCS11_PROVIDER_PATHS)
            if not provider:
                raise RuntimeError(
                    "OpenSSL pkcs11-provider not found; searched: "
                    + ", ".join(PKCS11_PROVIDER_PATHS)
                )
            module = self.pkcs11_module or first_existing(PKCS11_MODULE_PATHS)
            lines = [
                "openssl_conf = openssl_init",
                "",
                "[openssl_init]",
                "providers = provider_sect",
                "",
                "[provider_sect]",
                "default = default_sect",
                "pkcs11 = pkcs11_sect",
                "",
                "[default_sect]",
                "activate = 1",
                "",
                "[pkcs11_sect]",
                f"module = {provider}",
            ]
            if module:
                lines.append(f"pkcs11-module-path = {module}")
            lines.append("activate = 1")
            lines.append("")
            with open(self.openssl_conf, "w") as f:
                f.write("\n".join(lines))
            if not module:
                print(
                    "[setup] warning: no PKCS#11 module found (no p11-kit-proxy); "
                    "pass --pkcs11-module to pin one",
                    file=sys.stderr,
                )

        env = os.environ.copy()
        env["OPENSSL_CONF"] = self.openssl_conf
        synta, _gn, _kp = _synta()

        # Leaf: the certificate bound to the key object (the plugin's
        # identity URI with type=cert).
        leaf_uri = pkcs11_cert_uri(self.client_token)
        leaf_out = self._run_openssl("storeutl", "-certs", leaf_uri, env=env)
        leaf_pems = _pem_blocks(leaf_out)
        if not leaf_pems:
            raise RuntimeError(
                f"no certificate found for {redact_pkcs11_uri(leaf_uri)}; "
                "the token object must hold the client certificate "
                "(import it, e.g. with pkcs11-tool --write-object)"
            )
        leaf = synta.Certificate.from_pem(leaf_pems[0].encode())
        leaf_der = leaf.to_der()
        with open(self.client_token_leaf, "w") as f:
            f.write(synta.Certificate.to_pem(leaf).decode() + "\n")

        # KRB5 principal/realm from the SAN (the plugin's own decoder).
        san = parse_krb5_san(leaf_der)
        if san is None:
            raise RuntimeError(
                "client certificate has no KRB5 otherName SAN "
                f"(OID {KRB5_SAN_OID}); pass --realm and --principal explicitly"
            )
        self.token_principal, self.token_realm = san

        # Anchor: an explicit --client-ca file wins; otherwise search the
        # token for the issuer.
        if self.client_ca:
            anchor_ders = [c.to_der() for c in _certs_from_file(self.client_ca)]
            anchor_der = select_cert_anchor(leaf_der, anchor_ders)
            if anchor_der is None:
                raise RuntimeError(
                    f"client certificate does not verify against {self.client_ca}; "
                    "pass the CA that issued it"
                )
        else:
            token_uri = pkcs11_token_cert_uri(self.client_token)
            token_out = self._run_openssl("storeutl", "-certs", token_uri, env=env)
            candidate_ders = []
            for pem in _pem_blocks(token_out):
                der = synta.Certificate.from_pem(pem.encode()).to_der()
                if der != leaf_der:
                    candidate_ders.append(der)
            anchor_der = select_cert_anchor(leaf_der, candidate_ders)
            if anchor_der is None:
                raise RuntimeError(
                    "client certificate issuer not found on the token; "
                    "import it into the token or pass --client-ca <file>"
                )
        with open(self.client_token_anchor, "w") as f:
            f.write(
                synta.Certificate.to_pem(
                    synta.Certificate.from_der(anchor_der)
                ).decode()
                + "\n"
            )

    # -- PKI generation --

    def _newkey_args(self):
        """Return openssl -newkey and -pkeyopt arguments for the configured key type."""
        alg, pkeyopt = SUPPORTED_KEY_TYPES[self.key_type]
        args = ["-newkey", alg]
        if pkeyopt is not None:
            args += ["-pkeyopt", pkeyopt]
        return args

    def _is_pq_key_type(self):
        return self.key_type.startswith("mldsa")

    def _generate_pki(self):
        os.makedirs(self.certs_dir, exist_ok=True)
        newkey = self._newkey_args()

        # CA (self-signed)
        self._run_openssl(
            "req", "-x509", *newkey,
            "-keyout", self.ca_key, "-out", self.ca_cert,
            "-days", "1", "-noenc",
            "-subj", "/CN=PKINIT Test CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        )

        # KDC cert
        kdc_ext_cnf = os.path.join(self.certs_dir, "kdc-ext.cnf")
        with open(kdc_ext_cnf, "w") as f:
            f.write(textwrap.dedent(f"""\
                [kdc_exts]
                basicConstraints = CA:FALSE
                keyUsage = digitalSignature{'' if self._is_pq_key_type() else ',keyEncipherment'}
                extendedKeyUsage = 1.3.6.1.5.2.3.5
                subjectKeyIdentifier = hash
                authorityKeyIdentifier = keyid,issuer
                subjectAltName = @kdc_san

                [kdc_san]
                otherName = 1.3.6.1.5.2.2;SEQUENCE:krb5princ_kdc

                [krb5princ_kdc]
                realm = EXPLICIT:0,GeneralString:{self.realm}
                princ = EXPLICIT:1,SEQUENCE:princ_kdc

                [princ_kdc]
                nametype = EXPLICIT:0,INTEGER:2
                components = EXPLICIT:1,SEQUENCE:components_kdc

                [components_kdc]
                0.component = GeneralString:krbtgt
                1.component = GeneralString:{self.realm}
            """))

        kdc_csr = os.path.join(self.certs_dir, "kdc.csr")
        self._run_openssl(
            "req", "-new", *newkey,
            "-keyout", self.kdc_key, "-out", kdc_csr,
            "-noenc", "-subj", f"/CN=KDC {self.realm}",
        )
        self._run_openssl(
            "x509", "-req", "-in", kdc_csr,
            "-CA", self.ca_cert, "-CAkey", self.ca_key,
            "-CAcreateserial", "-out", self.kdc_cert,
            "-days", "1",
            "-extfile", kdc_ext_cnf, "-extensions", "kdc_exts",
        )

        if not self.client_token:
            # Client cert and key (skipped in token mode: the identity
            # certificate and private key live on the PKCS#11 token and are
            # never extracted to files).
            client_ext_cnf = os.path.join(self.certs_dir, "client-ext.cnf")
            with open(client_ext_cnf, "w") as f:
                f.write(textwrap.dedent(f"""\
                    [client_exts]
                    basicConstraints = CA:FALSE
                    keyUsage = digitalSignature
                    extendedKeyUsage = 1.3.6.1.5.2.3.4
                    subjectKeyIdentifier = hash
                    authorityKeyIdentifier = keyid,issuer
                    subjectAltName = @client_san

                    [client_san]
                    otherName = 1.3.6.1.5.2.2;SEQUENCE:krb5princ_client

                    [krb5princ_client]
                    realm = EXPLICIT:0,GeneralString:{self.realm}
                    princ = EXPLICIT:1,SEQUENCE:princ_client

                    [princ_client]
                    nametype = EXPLICIT:0,INTEGER:1
                    components = EXPLICIT:1,SEQUENCE:components_client

                    [components_client]
                    component = GeneralString:{self.principal}
                """))

            client_csr = os.path.join(self.certs_dir, "client.csr")
            self._run_openssl(
                "req", "-new", *newkey,
                "-keyout", self.client_key, "-out", client_csr,
                "-noenc", "-subj", f"/CN={self.principal}",
            )
            self._run_openssl(
                "x509", "-req", "-in", client_csr,
                "-CA", self.ca_cert, "-CAkey", self.ca_key,
                "-CAcreateserial", "-out", self.client_cert,
                "-days", "1",
                "-extfile", client_ext_cnf, "-extensions", "client_exts",
            )

        print(f"[setup] PKI generated in {self.certs_dir}", file=sys.stderr)

    def _run_openssl(self, *args, env=None):
        result = subprocess.run(
            ["openssl", *args],
            env=env,
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"openssl {args[0]} failed:\n{result.stderr}"
            )
        return result.stdout

    # -- Plugin validation --

    def _validate_plugins(self):
        if not self.kdc_plugin_so:
            raise RuntimeError("KDC plugin .so is required")
        if not os.path.isfile(self.kdc_plugin_so):
            raise RuntimeError(f"KDC plugin .so not found: {self.kdc_plugin_so}")
        if not self.client_plugin_so:
            raise RuntimeError("Client plugin .so is required")
        if not os.path.isfile(self.client_plugin_so):
            raise RuntimeError(f"Client plugin .so not found: {self.client_plugin_so}")
        os.makedirs(self.plugins_dir, exist_ok=True)
        self._link_system_preauth_plugins()

    def _find_system_preauth_dir(self):
        candidates = self._plugin_dir_candidates("preauth", [
            "/usr/lib64/krb5/plugins/preauth",
            "/usr/lib/krb5/plugins/preauth",
            "/usr/lib/x86_64-linux-gnu/krb5/plugins/preauth",
            "/usr/lib/aarch64-linux-gnu/krb5/plugins/preauth",
        ])
        for d in candidates:
            if os.path.isdir(d):
                return d
        return None

    def _link_system_preauth_plugins(self):
        """Symlink MIT's built-in preauth plugins (spake.so, otp.so, ...) into
        our redirected plugin_base_dir.

        [libdefaults] plugin_base_dir below points krb5 at self.plugins_dir
        for *all* dynamically-loaded plugins, not just ours -- so without
        this, the KDC and client both try (and fail) to autoload every
        preauth mechanism MIT ships by default from
        {plugin_base_dir}/preauth/, logging a spurious "unable to load
        plugin" error for each one on every exchange.
        """
        system_preauth_dir = self._find_system_preauth_dir()
        if not system_preauth_dir:
            return
        preauth_dir = os.path.join(self.plugins_dir, "preauth")
        os.makedirs(preauth_dir, exist_ok=True)
        for name in os.listdir(system_preauth_dir):
            if not name.endswith(".so"):
                continue
            link = os.path.join(preauth_dir, name)
            if not os.path.exists(link):
                os.symlink(os.path.join(system_preauth_dir, name), link)

    # -- System KDB module detection --

    def _find_db_module_dir(self):
        candidates = self._plugin_dir_candidates("kdb", [
            "/usr/lib64/krb5/plugins/kdb",
            "/usr/lib/krb5/plugins/kdb",
            "/usr/lib/x86_64-linux-gnu/krb5/plugins/kdb",
            "/usr/lib/aarch64-linux-gnu/krb5/plugins/kdb",
        ])
        for d in candidates:
            if os.path.isfile(os.path.join(d, "db2.so")):
                return d
        raise RuntimeError(
            "Cannot find db2.so KDB module; searched: " + ", ".join(candidates)
        )

    # -- Config generation --

    def _write_configs(self):
        db_module_dir = self._find_db_module_dir()
        pqc_line = ""
        if self.pqc_min_algorithm:
            # require_kem makes both sides refuse classic DH/ECDH outright,
            # rather than merely preferring ML-KEM.
            pqc_line = (
                f"\n                    pkinit_pqc_min_algorithm = {self.pqc_min_algorithm}"
                "\n                    pkinit_require_kem = true"
            )
        kdc_pqc_line = pqc_line
        if (self.pqc_min_algorithm or "").upper() in COMPOSITE_KEM_ALGORITHMS:
            kdc_pqc_line += (
                "\n                    pkinit_pqc_composite_algorithms = "
                f"{self.pqc_min_algorithm}"
            )

        # Client-side KDC trust: normally a static anchor; under TOFU the client
        # has no KDC-CA anchor and consults the broker instead, and needs
        # auto_fast_armor so the anonymous exchange runs first to establish it.
        if self.tofu_broker:
            # auto_fast_armor is a per-realm option: it makes the client obtain
            # an anonymous PKINIT FAST-armor ticket first, which is the exchange
            # that establishes trust before the authenticated one.
            client_pkinit = (
                "auto_fast_armor = true\n"
                "                    pkinit_kdc_trust_tofu = true\n"
                f"                    pkinit_kdc_trust_broker = {self.tofu_broker}"
            )
        else:
            client_pkinit = f"pkinit_anchors = FILE:{self.ca_cert}"
        client_pkinit += pqc_line
        if self.client_token:
            # The client identity comes from the PKCS#11 token. read_client_config
            # reads it with Profile::get_string_opt, which distinguishes an
            # absent key from an empty one, so it is safe to emit it under
            # [realms]: the libdefaults check finds it absent and moves on.
            # The PIN may be embedded in the URI -- acceptable because the
            # config lives in a 0700 dir.
            client_pkinit += (
                f"\n                    pkinit_identities = PKCS11:{self.client_token}"
            )

        # KDC identity. Under TOFU the KDC must *present* its issuing CA in the
        # reply's SignedData so the client can pin the CA (not just the leaf);
        # the identity loader treats the first cert as the leaf and the rest as
        # the chain, so a concatenated leaf+CA file makes the KDC send both.
        kdc_identity = f"FILE:{self.kdc_cert},{self.kdc_key}"
        if self.tofu_broker:
            kdc_chain = os.path.join(self.certs_dir, "kdc-chain.pem")
            with open(kdc_chain, "w") as out:
                for src in (self.kdc_cert, self.ca_cert):
                    with open(src) as inp:
                        out.write(inp.read())
            kdc_identity = f"FILE:{kdc_chain},{self.kdc_key}"

        krb5 = textwrap.dedent(f"""\
            [libdefaults]
                default_realm = {self.realm}
                rdns = false
                no_addresses = true
                plugin_base_dir = {self.plugins_dir}

            [realms]
                {self.realm} = {{
                    kdc = {self.kdc_socket}
                    {client_pkinit}
                }}

            [domain_realm]
                localhost = {self.realm}
                .localhost = {self.realm}

            [plugins]
                kdcpreauth = {{
                    module = pkinit:{self.kdc_plugin_so}
                }}
                clpreauth = {{
                    module = pkinit:{self.client_plugin_so}
                }}
                certauth = {{
                    module = pkinit:{self.kdc_plugin_so}
                }}
        """)

        kdc_anchor_line = f"FILE:{self.ca_cert}"
        if self.client_token:
            # The KDC must trust the client cert's issuing CA in addition to
            # the test-realm CA (the profile reader accepts repeated keys).
            kdc_anchor_line += (
                f"\n                    pkinit_anchors = FILE:{self.client_token_anchor}"
            )

        # A UNIX socket path is accepted in kdc_listen (krb5kdc serves it as a
        # stream socket) but rejected in kdc_tcp_listen, which is disabled.
        kdc = textwrap.dedent(f"""\
            [kdcdefaults]
                kdc_listen = {self.kdc_socket}
                kdc_tcp_listen = ""

            [dbmodules]
                db_module_dir = {db_module_dir}
                db = {{
                    db_library = db2
                    database_name = {self.db_path}
                }}

            [realms]
                {self.realm} = {{
                    database_module = db
                    acl_file = {self.acl_file}
                    key_stash_file = {self.stash}
                    kdc_listen = {self.kdc_socket}
                    kdc_tcp_listen = ""
                    max_life = 1h
                    max_renewable_life = 24h
                    supported_enctypes = {" ".join(f"{e}:normal" for e in ENCTYPES)}
                    pkinit_identity = {kdc_identity}
                    pkinit_anchors = {kdc_anchor_line}
                    default_principal_flags = +preauth
                    pkinit_eku_checking = none{kdc_pqc_line}
                }}

            [logging]
                kdc = FILE:{self.kdc_log}
        """)

        with open(self.krb5_conf, "w") as f:
            f.write(krb5)
        with open(self.kdc_conf, "w") as f:
            f.write(kdc)
        with open(self.acl_file, "w") as f:
            f.write(f"*/admin@{self.realm} *\n")

    # -- Low-level helpers --

    def _run(self, *cmd, input=None):
        result = subprocess.run(
            cmd, env=self.env,
            input=input, capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Command failed: {' '.join(cmd)}\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )
        return result.stdout

    def _kadmin_local(self, *query):
        self._run("kadmin.local", "-r", self.realm, "-q", " ".join(query))

    # -- Lifecycle --

    def create_db(self, master_password="pkinit-test-pw"):
        if self.client_token and self.token_realm is None:
            self.load_client_token_identity()
        self._generate_pki()
        self._validate_plugins()
        self._write_configs()
        self._run(
            "kdb5_util", "create", "-r", self.realm,
            "-s", "-P", master_password,
        )

    def start(self, master_password="pkinit-test-pw"):
        if not os.path.exists(self.db_path + ".db") and not os.path.exists(self.db_path):
            self.create_db(master_password)

        log_fd = open(self.kdc_log, "a")
        self._kdc_proc = subprocess.Popen(
            ["krb5kdc", "-n", "-r", self.realm],
            env=self.env, stdout=log_fd, stderr=log_fd,
        )
        atexit.register(self.stop)
        self._wait_for_kdc()
        print(
            f"[setup] KDC started (pid {self._kdc_proc.pid}) "
            f"listening on {self.kdc_socket}",
            file=sys.stderr,
        )

    def _wait_for_kdc(self, timeout=10):
        import socket
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._kdc_proc.poll() is not None:
                raise RuntimeError(
                    "krb5kdc exited immediately; check " + self.kdc_log
                )
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.settimeout(0.2)
                    s.connect(self.kdc_socket)
                    return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError(f"KDC not listening after {timeout}s; see {self.kdc_log}")

    def stop(self):
        if self._kdc_proc and self._kdc_proc.poll() is None:
            self._kdc_proc.terminate()
            try:
                self._kdc_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._kdc_proc.kill()
            print("[setup] KDC stopped", file=sys.stderr)
        self._kdc_proc = None
        if self._kdc_socket_dir:
            shutil.rmtree(self._kdc_socket_dir, ignore_errors=True)
            self._kdc_socket_dir = None

    # -- Principal management --

    def addprinc(self, name, password=None):
        if password is not None:
            self._kadmin_local("addprinc", "-pw", password, name)
        else:
            self._kadmin_local("addprinc", "-randkey", name)

    def modprinc(self, *flags):
        self._kadmin_local("modprinc", *flags)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Start an ephemeral Kerberos realm with PKINIT"
    )
    parser.add_argument("--testdir", default=None)
    parser.add_argument("--realm", default=None,
                        help=f"Kerberos realm (default: {REALM}; in token mode "
                             "derived from the token cert's KRB5 SAN)")
    parser.add_argument("--kdc-socket", metavar="PATH", default=None,
                        help="UNIX domain socket for the KDC to listen on "
                             "(default: kdc.sock in a fresh short temporary "
                             "directory, removed on exit)")
    parser.add_argument("--plugin-so",
                        help="Path to plugin .so (sets both KDC and client)")
    parser.add_argument("--kdc-plugin-so",
                        help="Path to KDC-side preauth plugin .so")
    parser.add_argument("--client-plugin-so",
                        help="Path to client-side preauth plugin .so")
    parser.add_argument("--env-file", metavar="FILE",
                        help="Write shell-sourceable env vars to FILE")
    parser.add_argument("--principal", default=None,
                        help="Client principal name (default: user; in token "
                             "mode derived from the token cert's KRB5 SAN)")
    parser.add_argument("--key-type", default="ec:P-256",
                        choices=sorted(SUPPORTED_KEY_TYPES),
                        help="Certificate key type (default: ec:P-256)")
    parser.add_argument("--pqc-min-algorithm",
                        default=DEFAULT_PQC_MIN_ALGORITHM,
                        help="Minimum ML-KEM algorithm for the key exchange "
                             f"(default: {DEFAULT_PQC_MIN_ALGORITHM}); "
                             f"'{CLASSIC_KEX}' selects classic DH/ECDH, for "
                             "interop with MIT's pkinit.so")
    parser.add_argument("--tofu-broker", default=None, metavar="SOCKET",
                        help="Enable KDC-CA trust-on-first-use: client consults "
                             "the broker at this Unix socket, has no static "
                             "KDC-CA anchor, and uses auto_fast_armor")
    parser.add_argument("--client-token", metavar="URI", default=None,
                        help="PKCS#11 URI of the client identity object "
                             "(pkcs11:token=...;object=...;type=private"
                             "?pin-value=...). The certificate on the token "
                             "is used as the PKINIT client identity; the "
                             "private key never leaves the token. Realm and "
                             "principal default to the cert's KRB5 SAN when "
                             "not given.")
    parser.add_argument("--client-ca", metavar="FILE", default=None,
                        help="PEM file of the CA that issued the client "
                             "certificate (adds a second pkinit_anchors "
                             "entry to the KDC). Defaults to the issuer "
                             "certificate on the token.")
    parser.add_argument("--krb5-prefix", metavar="DIR",
                        default=os.environ.get("KRB5_PREFIX") or None,
                        help="Use the MIT krb5 installed under DIR (KDC, admin "
                             "tools, kinit, libraries, KDB and preauth "
                             "plugins) instead of the system one "
                             "(default: $KRB5_PREFIX)")
    parser.add_argument("--pkcs11-module", metavar="FILE", default=None,
                        help="Path of the PKCS#11 module (e.g. a PKCS#11 "
                             "provider .so) pinned via pkcs11-module-path in "
                             "the generated OpenSSL config. Defaults to the "
                             "system p11-kit proxy when present.")
    args = parser.parse_args()

    kdc_so = args.kdc_plugin_so or args.plugin_so
    client_so = args.client_plugin_so or args.plugin_so
    if not kdc_so or not client_so:
        parser.error("Provide --plugin-so, or both --kdc-plugin-so and --client-plugin-so")

    realm = PkinitRealm(
        testdir=args.testdir,
        realm=args.realm,
        kdc_socket=args.kdc_socket,
        kdc_plugin_so=kdc_so,
        client_plugin_so=client_so,
        principal=args.principal,
        key_type=args.key_type,
        pqc_min_algorithm=args.pqc_min_algorithm,
        tofu_broker=args.tofu_broker,
        client_token=args.client_token,
        client_ca=args.client_ca,
        pkcs11_module=args.pkcs11_module,
        krb5_prefix=args.krb5_prefix,
    )
    if realm.client_token:
        realm.load_client_token_identity()
        if args.realm is None:
            realm.realm = realm.token_realm
        if args.principal is None:
            realm.principal = realm.token_principal
        print(
            f"[setup] token identity: {realm.principal}@{realm.realm} "
            f"(from certificate SAN)",
            file=sys.stderr,
        )
    realm.start()

    # Client principal (PKINIT only, no password)
    realm.addprinc(f"{realm.principal}@{realm.realm}")

    # Anonymous PKINIT principal
    realm.addprinc(f"WELLKNOWN/ANONYMOUS@{realm.realm}")

    # KRB5_TRACE is overridden below to realm.client_trace: kinit/klist run
    # under this env-file and must not write into the KDC's own trace file
    # (realm.kdc_trace, used by realm.env to launch krb5kdc), or KDC-side
    # and client-side trace lines interleave in one file with no way to
    # tell them apart.
    env_lines = "\n".join(
        f'export {k}="{v}"' for k, v in realm.env.items()
        if k.startswith("KRB5") and k != "KRB5_TRACE"
    )
    env_lines += f'\nexport KRB5_TRACE="{realm.client_trace}"'
    for k, v in realm.prefix_env().items():
        env_lines += f'\nexport {k}="{v}"'
    if realm.client_token:
        # Token mode: the plugin loads the identity from the PKCS#11 token at
        # runtime, so no cert/key file exports. OPENSSL_CONF is exported so
        # the pkcs11-provider is active in the client shell.
        env_lines += f'\nexport PKINIT_CLIENT_IDENTITY="{realm.client_token}"'
        env_lines += f'\nexport OPENSSL_CONF="{realm.openssl_conf}"'
    else:
        env_lines += f'\nexport PKINIT_CLIENT_CERT="{realm.client_cert}"'
        env_lines += f'\nexport PKINIT_CLIENT_KEY="{realm.client_key}"'
    env_lines += f'\nexport PKINIT_CA_CERT="{realm.ca_cert}"'
    env_lines += f'\nexport PKINIT_REALM="{realm.realm}"'
    env_lines += f'\nexport PKINIT_PRINCIPAL="{realm.principal}"'
    env_lines += f'\nexport PKINIT_KDC_SOCKET="{realm.kdc_socket}"'
    env_lines += f'\nexport SETUP_PID="{os.getpid()}"'

    if args.env_file:
        with open(args.env_file, "w") as f:
            f.write(env_lines + "\n")
        print(f"[setup] env written to {args.env_file}", file=sys.stderr)
        print("[setup] Blocking until signalled (SIGTERM or SIGINT)...",
              file=sys.stderr)
    else:
        print("\n# Source these in your shell:")
        print(env_lines)
        print()
        print("[setup] Press Ctrl-C to stop the KDC and clean up",
              file=sys.stderr)

    def _stop(_sig, _frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, _stop)

    try:
        signal.pause()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        realm.stop()


if __name__ == "__main__":
    main()
