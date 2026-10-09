"""Generate the SSL Certificate Authority and test certificates.

Python port of Apache::TestSSLCA. Builds, under ``t/conf/ssl/ca/asf``, a self-
signed CA plus server and client certificates that the SSL test configs reference
(``server.crt``/``server.pem``, ``server_des3.*``, ``client_ok``/``client_snakeoil``/
``client_revoked``/``client_colon``, proxy client PEMs, and a CRL). The layout and
filenames match the Perl framework so the existing ``t/conf/ssl/*.conf.in`` files
work unchanged.

Notes vs. the Perl original:
* RSA keys are 2048-bit, digest sha256 (matches modern openssl defaults).
* DSA server variants (``server_dsa`` etc.) are generated too, for config files
  that may reference them; on OpenSSL 3.x DSA keygen still works.
* All passphrases are ``httpd`` (``$pass`` in the original).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

PASS = "httpd"
DAYS = "365"
DGST = "sha256"
EMAIL_FIELD = "emailAddress"

# CA distinguished name (ca_dn{asf}).
CA_DN = {
    "C": "US",
    "ST": "California",
    "L": "San Francisco",
    "O": "ASF",
    "OU": "httpd-test",
    "CN": "",
    EMAIL_FIELD: "test-dev@httpd.apache.org",
}

# Per-cert DN overrides (cert_dn). CN for server* is set to the servername at
# generation time (matching generate() in the Perl module).
CERT_DN: dict[str, dict[str, str]] = {
    "client_snakeoil": {
        "C": "AU", "ST": "Queensland", "L": "Mackay",
        "O": "Snake Oil, Ltd.", "OU": "Staff",
    },
    "client_ok": {},
    "client_colon": {"CN": "user:colon"},
    "client_revoked": {},
    "server": {"CN": "localhost", "OU": "httpd-test/rsa-test"},
    "server2": {"CN": "localhost", "OU": "httpd-test/rsa-test-2"},
    "server_des3": {"CN": "localhost", "OU": "httpd-test/rsa-des3-test"},
    "server2_des3": {"CN": "localhost", "OU": "httpd-test/rsa-des3-test-2"},
}
# DSA variants of every server cert (Perl derives these dynamically).
for _k in list(CERT_DN):
    if _k.startswith("server"):
        _dsa = dict(CERT_DN[_k])
        _dsa["OU"] = _dsa.get("OU", "").replace("rsa", "dsa")
        CERT_DN[f"{_k}_dsa"] = _dsa


class SSLCA:
    def __init__(self, ca_root: Path, servername: str, *, openssl: str = "openssl") -> None:
        # ca_root is e.g. t/conf/ssl/ca ; the CA tree lives under ca_root/asf.
        self.root = ca_root
        self.ca = "asf"
        self.servername = servername
        self.openssl = openssl
        self.dir = ca_root / self.ca

    # -- helpers ----------------------------------------------------------

    def _run(self, *args: str, cwd: Path) -> None:
        cmd = [self.openssl, *args]
        proc = subprocess.run(  # noqa: S603 - trusted openssl invocation
            cmd, cwd=cwd, capture_output=True, text=True, check=False
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"openssl failed: {' '.join(cmd)}\n{proc.stdout}\n{proc.stderr}"
            )

    def _dn(self, name: str) -> dict[str, str]:
        dn = dict(CA_DN)
        dn["CN"] = dn["CN"] or name
        dn.update(CERT_DN.get(name, {}))
        if name.startswith("server"):
            dn["CN"] = self.servername
        return dn

    def _config_file(self, name: str) -> Path:
        """Write conf/<name>.cnf (openssl config) and return its path."""
        dn = self._dn(name)
        cnf = self.dir / "conf" / f"{name}.cnf"
        cnf.write_text(
            f"mail = {dn[EMAIL_FIELD]}\n"
            f"CN = {dn['CN']}\n\n"
            "[ req ]\n"
            "distinguished_name = req_distinguished_name\n"
            "attributes = req_attributes\n"
            "prompt = no\n"
            "default_bits = 2048\n"
            f"output_password = {PASS}\n\n"
            "[ req_distinguished_name ]\n"
            f"C = {dn['C']}\n"
            f"ST = {dn['ST']}\n"
            f"L = {dn['L']}\n"
            f"O = {dn['O']}\n"
            f"OU = {dn['OU']}\n"
            "CN = $CN\n"
            f"{EMAIL_FIELD} = $mail\n\n"
            "[ req_attributes ]\n"
            f"challengePassword = {PASS}\n\n"
            "[ ca ]\n"
            "default_ca = CA_default\n\n"
            "[ CA_default ]\n"
            "certs = certs\n"
            "new_certs_dir = newcerts\n"
            "crl_dir = crl\n"
            "database = index.txt\n"
            "serial = serial\n"
            "certificate = certs/ca.crt\n"
            "crl = crl/ca-bundle.crl\n"
            "private_key = keys/ca.pem\n"
            "default_days = 365\n"
            "default_crl_days = 365\n"
            f"default_md = {DGST}\n"
            "preserve = no\n\n"
            "[ policy_anything ]\n"
            "countryName = optional\n"
            "stateOrProvinceName = optional\n"
            "localityName = optional\n"
            "organizationName = optional\n"
            "organizationalUnitName = optional\n"
            "commonName = supplied\n"
            f"{EMAIL_FIELD} = optional\n\n"
            "[ client_ok_ext ]\n"
            "nsComment = This Is A Comment\n"
            # Custom OID extension carrying the DER-encoded UTF8String "Lemons"
            # (0c=UTF8String, 06=len 6, 4c656d6f6e73="Lemons"). t/ssl/require.t's
            # certext location asserts: "Lemons" in PeerExtList(<this OID>).
            # Faithful to Apache::TestSSLCA's client_ok_ext.
            "1.3.6.1.4.1.18060.12.0 = DER:0c064c656d6f6e73\n"
            "subjectAltName = email:$mail\n\n"
            "[ client_ext ]\n"
            "extendedKeyUsage = clientAuth\n\n"
            "[ server_ext ]\n"
            "subjectAltName = DNS:$CN\n"
            "extendedKeyUsage = serverAuth\n"
            "subjectKeyIdentifier = hash\n"
            "authorityKeyIdentifier = keyid,issuer\n\n"
            "[ ca_ext ]\n"
            "subjectKeyIdentifier = hash\n"
            "authorityKeyIdentifier = keyid:always,issuer\n"
            "basicConstraints = critical,CA:true\n"
            # OpenSSL 3.x's verifier rejects a CA cert used to sign certs unless
            # it carries keyCertSign (and cRLSign for the CRL). The Perl-era
            # certs predate this strictness; add it so modern clients (httpx via
            # OpenSSL 3) can verify the chain.
            "keyUsage = critical,keyCertSign,cRLSign\n"
        )
        return cnf

    # -- generation steps -------------------------------------------------

    def _init_dirs(self) -> None:
        for d in ("keys", "newcerts", "certs", "crl", "export", "csr", "conf", "proxy"):
            (self.dir / d).mkdir(parents=True, exist_ok=True)
        (self.dir / "index.txt").write_text("")
        (self.dir / "serial").write_text("01\n")

    def _new_ca(self) -> None:
        self._config_file("ca")
        self._run(
            "req", "-new", "-x509", "-extensions", "ca_ext",
            "-keyout", "keys/ca.pem", "-out", "certs/ca.crt",
            "-days", DAYS, "-config", "conf/ca.cnf",
            "-passout", f"pass:{PASS}",
            cwd=self.dir,
        )

    def _new_key(self, name: str) -> None:
        out = f"keys/{name}.pem"
        if "dsa" in name:
            param = self.dir / "dsa-param"
            if not param.exists():
                self._run("dsaparam", "-out", "dsa-param", "2048", cwd=self.dir)
            args = ["gendsa", "-out", out]
            if "_des3" in name:
                args += ["-des3", "-passout", f"pass:{PASS}"]
            args += ["dsa-param"]
            self._run(*args, cwd=self.dir)
        else:
            args = ["genrsa", "-out", out]
            if "_des3" in name:
                args += ["-des3", "-passout", f"pass:{PASS}"]
            args += ["2048"]
            self._run(*args, cwd=self.dir)

    def _new_cert(self, name: str) -> None:
        self._config_file(name)
        self._run(
            "req", "-new", "-key", f"keys/{name}.pem", "-out", f"csr/{name}.csr",
            "-passin", f"pass:{PASS}", "-passout", f"pass:{PASS}",
            "-config", f"conf/{name}.cnf",
            cwd=self.dir,
        )
        exts: list[str] = []
        if "client" in name:
            exts = ["-extensions", "client_ext"]
        if "client_ok" in name:
            exts = ["-extensions", "client_ok_ext"]
        if "server" in name:
            exts = ["-extensions", "server_ext"]
        self._run(
            "ca", "-policy", "policy_anything",
            "-in", f"csr/{name}.csr", "-out", f"certs/{name}.crt",
            "-passin", f"pass:{PASS}", "-config", f"conf/{name}.cnf",
            "-batch", *exts,
            cwd=self.dir,
        )

    def _make_proxy_cert(self, name: str) -> None:
        """Concatenate cert + key into proxy/<name>.pem (make_proxy_cert)."""
        crt = (self.dir / "certs" / f"{name}.crt").read_text()
        key = (self.dir / "keys" / f"{name}.pem").read_text()
        (self.dir / "proxy" / f"{name}.pem").write_text(crt + key)

    def _revoke_cert(self, name: str) -> None:
        self._run(
            "ca", "-revoke", f"certs/{name}.crt",
            "-config", "conf/ca.cnf", "-passin", f"pass:{PASS}",
            cwd=self.dir,
        )
        self._run(
            "ca", "-gencrl", "-out", "crl/ca-bundle.crl",
            "-config", "conf/ca.cnf", "-passin", f"pass:{PASS}",
            cwd=self.dir,
        )

    def generate(self) -> Path:
        """Build the full CA tree (idempotent). Returns the CA root dir."""
        if self.dir.is_dir() and (self.dir / "certs" / "ca.crt").exists():
            return self.root  # already generated
        self._init_dirs()
        self._new_ca()
        # Ensure a CRL exists even if nothing is revoked.
        for name in CERT_DN:
            self._new_key(name)
            self._new_cert(name)
            if name.endswith("_revoked"):
                self._revoke_cert(name)
            if name.startswith("client_"):
                self._make_proxy_cert(name)
        # Guarantee crl/ca-bundle.crl exists (referenced by SSLCARevocationFile).
        crl = self.dir / "crl" / "ca-bundle.crl"
        if not crl.exists():
            self._run(
                "ca", "-gencrl", "-out", "crl/ca-bundle.crl",
                "-config", "conf/ca.cnf", "-passin", f"pass:{PASS}",
                cwd=self.dir,
            )
        return self.root
