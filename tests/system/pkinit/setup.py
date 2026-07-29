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
import signal
import subprocess
import sys
import tempfile
import textwrap
import time

REALM = "PKINIT.TEST"
PORTBASE = 63100


class PkinitRealm:
    def __init__(self, testdir=None, realm=REALM, portbase=PORTBASE,
                 kdc_plugin_so=None, client_plugin_so=None, principal="user"):
        self.realm = realm
        self.portbase = portbase
        self.principal = principal
        self.testdir = os.path.abspath(
            testdir or tempfile.mkdtemp(prefix="pkinit-test-")
        )
        self.kdc_plugin_so = os.path.abspath(kdc_plugin_so) if kdc_plugin_so else None
        self.client_plugin_so = os.path.abspath(client_plugin_so) if client_plugin_so else None
        self._kdc_proc = None

        self.krb5_conf = os.path.join(self.testdir, "krb5.conf")
        self.kdc_conf = os.path.join(self.testdir, "kdc.conf")
        self.kdc_log = os.path.join(self.testdir, "kdc.log")
        self.db_path = os.path.join(self.testdir, "db")
        self.acl_file = os.path.join(self.testdir, "acl")
        self.stash = os.path.join(self.testdir, "stash")
        self.ccache = os.path.join(self.testdir, "ccache")

        self.certs_dir = os.path.join(self.testdir, "certs")
        self.plugins_dir = os.path.join(self.testdir, "plugins")

        self.ca_cert = os.path.join(self.certs_dir, "ca.pem")
        self.ca_key = os.path.join(self.certs_dir, "ca-key.pem")
        self.kdc_cert = os.path.join(self.certs_dir, "kdc.pem")
        self.kdc_key = os.path.join(self.certs_dir, "kdc-key.pem")
        self.client_cert = os.path.join(self.certs_dir, "client.pem")
        self.client_key = os.path.join(self.certs_dir, "client-key.pem")

        os.makedirs(self.testdir, exist_ok=True)

    @property
    def env(self):
        e = os.environ.copy()
        e["KRB5_CONFIG"] = self.krb5_conf
        e["KRB5_KDC_PROFILE"] = self.kdc_conf
        e["KRB5CCNAME"] = f"FILE:{self.ccache}"
        e["KRB5RCACHEDIR"] = self.testdir
        return e

    # -- PKI generation --

    def _generate_pki(self):
        os.makedirs(self.certs_dir, exist_ok=True)

        # CA (self-signed, EC P-256)
        self._run_openssl(
            "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:P-256",
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
                keyUsage = digitalSignature,keyEncipherment
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
            "req", "-new", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:P-256",
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

        # Client cert
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
            "req", "-new", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:P-256",
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

    def _run_openssl(self, *args):
        result = subprocess.run(
            ["openssl", *args],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"openssl {args[0]} failed:\n{result.stderr}"
            )

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

    # -- System KDB module detection --

    @staticmethod
    def _find_db_module_dir():
        candidates = [
            "/usr/lib64/krb5/plugins/kdb",
            "/usr/lib/krb5/plugins/kdb",
            "/usr/lib/x86_64-linux-gnu/krb5/plugins/kdb",
            "/usr/lib/aarch64-linux-gnu/krb5/plugins/kdb",
        ]
        for d in candidates:
            if os.path.isfile(os.path.join(d, "db2.so")):
                return d
        raise RuntimeError(
            "Cannot find db2.so KDB module; searched: " + ", ".join(candidates)
        )

    # -- Config generation --

    def _write_configs(self):
        db_module_dir = self._find_db_module_dir()

        krb5 = textwrap.dedent(f"""\
            [libdefaults]
                default_realm = {self.realm}
                rdns = false
                no_addresses = true
                plugin_base_dir = {self.plugins_dir}

            [realms]
                {self.realm} = {{
                    kdc = 127.0.0.1:{self.portbase}
                    admin_server = 127.0.0.1:{self.portbase + 1}
                    pkinit_anchors = FILE:{self.ca_cert}
                    pkinit_identities = FILE:{self.client_cert},{self.client_key}
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

        kdc = textwrap.dedent(f"""\
            [kdcdefaults]
                kdc_ports = {self.portbase}
                kdc_tcp_ports = {self.portbase}

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
                    kdc_ports = {self.portbase}
                    kdc_tcp_ports = {self.portbase}
                    max_life = 1h
                    max_renewable_life = 24h
                    supported_enctypes = aes256-cts:normal aes128-cts:normal
                    pkinit_identity = FILE:{self.kdc_cert},{self.kdc_key}
                    pkinit_anchors = FILE:{self.ca_cert}
                    default_principal_flags = +preauth
                    pkinit_eku_checking = none
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
        self._wait_for_kdc()
        atexit.register(self.stop)
        print(
            f"[setup] KDC started (pid {self._kdc_proc.pid}) "
            f"listening on port {self.portbase}",
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
                with socket.create_connection(
                    ("127.0.0.1", self.portbase), timeout=0.2
                ):
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
    parser.add_argument("--realm", default=REALM)
    parser.add_argument("--portbase", type=int, default=PORTBASE)
    parser.add_argument("--plugin-so",
                        help="Path to plugin .so (sets both KDC and client)")
    parser.add_argument("--kdc-plugin-so",
                        help="Path to KDC-side preauth plugin .so")
    parser.add_argument("--client-plugin-so",
                        help="Path to client-side preauth plugin .so")
    parser.add_argument("--env-file", metavar="FILE",
                        help="Write shell-sourceable env vars to FILE")
    parser.add_argument("--principal", default="user",
                        help="Client principal name (default: user)")
    args = parser.parse_args()

    kdc_so = args.kdc_plugin_so or args.plugin_so
    client_so = args.client_plugin_so or args.plugin_so
    if not kdc_so or not client_so:
        parser.error("Provide --plugin-so, or both --kdc-plugin-so and --client-plugin-so")

    realm = PkinitRealm(
        testdir=args.testdir,
        realm=args.realm,
        portbase=args.portbase,
        kdc_plugin_so=kdc_so,
        client_plugin_so=client_so,
        principal=args.principal,
    )
    realm.start()

    # Client principal (PKINIT only, no password)
    realm.addprinc(f"{args.principal}@{args.realm}")

    # Anonymous PKINIT principal
    realm.addprinc(f"WELLKNOWN/ANONYMOUS@{args.realm}")

    env_lines = "\n".join(
        f'export {k}="{v}"' for k, v in realm.env.items()
        if k.startswith("KRB5")
    )
    env_lines += f'\nexport PKINIT_CLIENT_CERT="{realm.client_cert}"'
    env_lines += f'\nexport PKINIT_CLIENT_KEY="{realm.client_key}"'
    env_lines += f'\nexport PKINIT_CA_CERT="{realm.ca_cert}"'
    env_lines += f'\nexport PKINIT_REALM="{args.realm}"'
    env_lines += f'\nexport PKINIT_PRINCIPAL="{args.principal}"'
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
