"""The certificate authority tree of the classic (Apache::Test) SSL tests.

Python port of Apache::TestSSLCA on the ``cryptography`` package, like the
rest of the certificate code of this suite (pyhttpd.certs); no openssl command
line tool is needed to build it. It writes, under ``<ca_root>/asf``, a
self-signed CA plus server and client certificates in the layout and under
the file names of the Perl framework, so that the ``t/conf/ssl/*.conf.in``
files work unchanged:

  certs/ca.crt, keys/ca.pem               the CA
  certs/<name>.crt, keys/<name>.pem       server, server2, server_aes256,
                                          server2_aes256 (+ _ecdsa variants),
                                          client_ok, client_snakeoil,
                                          client_colon, client_revoked
  proxy/<client>.pem                      certificate and key of each client
  crl/ca-bundle.crl                       the CRL, with client_revoked in it
  index.txt, serial                       the database of "openssl ca" /
                                          "openssl ocsp -index", which
                                          t/htdocs/modules/cgi/ocsp.pl uses

Differences from the Perl original:
* RSA keys are 2048 bit, digest sha256 (what modern openssl defaults to).
* The CA certificate carries keyCertSign and cRLSign: OpenSSL 3 refuses to
  verify a chain through a CA without them.
* DSA server variants (``server_ecdsa`` etc.) are generated too, for config files
  that may reference them.
* Keys are PKCS#8 (openssl 3 writes that too); the _aes256 ones and the CA key
  are encrypted with the passphrase ``httpd``.
"""

import datetime
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import (ExtendedKeyUsageOID, NameOID,
                                   ObjectIdentifier)

PASS = "httpd"
DAYS = 365
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
CERT_DN: Dict[str, Dict[str, str]] = {
    "client_snakeoil": {
        "C": "AU", "ST": "Queensland", "L": "Mackay",
        "O": "Snake Oil, Ltd.", "OU": "Staff",
    },
    "client_ok": {},
    "client_colon": {"CN": "user:colon"},
    "client_revoked": {},
    "server": {"CN": "localhost", "OU": "httpd-test/rsa-test"},
    "server2": {"CN": "localhost", "OU": "httpd-test/rsa-test-2"},
    "server_aes256": {"CN": "localhost", "OU": "httpd-test/rsa-aes256-test"},
    "server2_aes256": {"CN": "localhost", "OU": "httpd-test/rsa-aes256-test-2"},
}
# DSA variants of every server cert (Perl derives these dynamically).
for _k in list(CERT_DN):
    if _k.startswith("server"):
        _ecdsa = dict(CERT_DN[_k])
        _ecdsa["OU"] = _ecdsa.get("OU", "").replace("rsa", "ecdsa")
        CERT_DN[f"{_k}_ecdsa"] = _ecdsa

# DN attributes in the order "openssl req" and the policy of "openssl ca" put them
_DN_ATTRS: List[Tuple[str, ObjectIdentifier]] = [
    ("C", NameOID.COUNTRY_NAME),
    ("ST", NameOID.STATE_OR_PROVINCE_NAME),
    ("L", NameOID.LOCALITY_NAME),
    ("O", NameOID.ORGANIZATION_NAME),
    ("OU", NameOID.ORGANIZATIONAL_UNIT_NAME),
    ("CN", NameOID.COMMON_NAME),
    (EMAIL_FIELD, NameOID.EMAIL_ADDRESS),
]

# nsComment, and the custom OID of the client_ok certificate: the DER encoded
# UTF8String "Lemons" (0c=UTF8String, 06=length, 4c656d6f6e73="Lemons"), which
# t/ssl/require.t's certext location asserts: "Lemons" in PeerExtList(<oid>).
_NS_COMMENT_OID = ObjectIdentifier("2.16.840.1.113730.1.13")
_CLIENT_OK_OID = ObjectIdentifier("1.3.6.1.4.1.18060.12.0")
_NS_COMMENT = b"This Is A Comment"


def _openssl_time(t: datetime.datetime) -> str:
    return t.strftime("%y%m%d%H%M%SZ")


def x509_name_hash(name: x509.Name) -> str:
    """The hash OpenSSL names certificate and CRL files in a directory by
    (``openssl x509 -hash``, ``openssl crl -hash``): the first four bytes,
    little endian, of the SHA-1 of the canonical form of the name. In that
    form every value is a UTF8String, with leading and trailing whitespace
    removed, runs of whitespace collapsed to one space, and ASCII upper case
    made lower case.
    """
    canon = []
    for rdn in name.rdns:
        canon.append(x509.RelativeDistinguishedName([
            x509.NameAttribute(
                a.oid, " ".join(a.value.split()).translate(_ASCII_LOWER),
                _type=_ASN1Type.UTF8String)
            for a in rdn]))
    der = x509.Name(canon).public_bytes()
    # the canonical encoding is the RDNs without the SEQUENCE around them
    if der[1] < 0x80:
        body = der[2:]
    else:
        body = der[2 + (der[1] & 0x7F):]
    return f"{int.from_bytes(hashlib.sha1(body).digest()[:4], 'little'):08x}"


_ASCII_LOWER = {c: c + 32 for c in range(ord("A"), ord("Z") + 1)}


class SSLCA:
    def __init__(self, ca_root: Path, servername: str, *,
                 openssl: Optional[str] = None) -> None:
        # ca_root is e.g. t/conf/ssl/ca ; the CA tree lives under ca_root/asf.
        # *openssl* is accepted for compatibility and unused.
        self.root = Path(ca_root)
        self.ca = "asf"
        self.servername = servername
        self.dir = self.root / self.ca
        self._serial = 1
        self._index: List[str] = []
        self._ca_key = None
        self._ca_cert: Optional[x509.Certificate] = None

    # -- helpers ----------------------------------------------------------

    def _dn(self, name: str) -> Dict[str, str]:
        dn = dict(CA_DN)
        dn["CN"] = dn["CN"] or name
        dn.update(CERT_DN.get(name, {}))
        if name.startswith("server"):
            dn["CN"] = self.servername
        return dn

    @staticmethod
    def _x509_name(dn: Dict[str, str]) -> x509.Name:
        return x509.Name([x509.NameAttribute(oid, dn[key])
                          for key, oid in _DN_ATTRS if dn.get(key)])

    @staticmethod
    def _slash_dn(dn: Dict[str, str]) -> str:
        # as in the database of "openssl ca": a "/" in a value is escaped
        return "".join(f"/{key}={dn[key].replace('/', chr(92) + '/')}"
                       for key, _ in _DN_ATTRS if dn.get(key))

    @staticmethod
    def _key_pem(key, encrypted: bool) -> bytes:
        enc = (serialization.PrivateFormat.PKCS8.encryption_builder()
            .pbes2_sha256_and_aes256_cbc()
            .build(PASS.encode())
               if encrypted else serialization.NoEncryption())
        return key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8, enc)

    def _write(self, rel: str, data: bytes) -> None:
        (self.dir / rel).write_bytes(data)

    # -- generation steps -------------------------------------------------

    def _init_dirs(self) -> None:
        for d in ("keys", "newcerts", "certs", "crl", "export", "csr", "conf", "proxy"):
            (self.dir / d).mkdir(parents=True, exist_ok=True)

    def _new_ca(self, now: datetime.datetime) -> None:
        dn = self._dn("ca")
        name = self._x509_name(dn)
        self._ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ski = x509.SubjectKeyIdentifier.from_public_key(self._ca_key.public_key())
        self._ca_cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=DAYS))
            .add_extension(ski, critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
                           critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            # OpenSSL 3's verifier rejects a CA cert used to sign certs unless
            # it carries keyCertSign (and cRLSign for the CRL).
            .add_extension(x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False), critical=True)
            .sign(self._ca_key, hashes.SHA256())
        )
        self._write("keys/ca.pem", self._key_pem(self._ca_key, True))
        self._write("certs/ca.crt", self._ca_cert.public_bytes(serialization.Encoding.PEM))

    def _new_key(self, name: str):
        if "ecdsa" in name:
            key = ec.generate_private_key(ec.SECP256R1())
        else:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._write(f"keys/{name}.pem", self._key_pem(key, "_aes256" in name))
        return key

    def _extensions(self, name: str, dn: Dict[str, str], pub) -> List[Tuple[x509.ExtensionType, bool]]:
        exts: List[Tuple[x509.ExtensionType, bool]] = []
        mail = dn[EMAIL_FIELD]
        if "client_ok" in name:                                   # client_ok_ext
            exts.append((x509.UnrecognizedExtension(
                _NS_COMMENT_OID, bytes([0x16, len(_NS_COMMENT)]) + _NS_COMMENT), False))
            exts.append((x509.UnrecognizedExtension(
                _CLIENT_OK_OID, bytes.fromhex("0c064c656d6f6e73")), False))
            exts.append((x509.SubjectAlternativeName([x509.RFC822Name(mail)]), False))
        elif "client" in name:                                    # client_ext
            exts.append((x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False))
        if "server" in name:                                      # server_ext
            exts.append((x509.SubjectAlternativeName([x509.DNSName(dn["CN"])]), False))
            exts.append((x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False))
        return exts

    def _new_cert(self, name: str, key, now: datetime.datetime) -> x509.Certificate:
        dn = self._dn(name)
        ca_ski = x509.SubjectKeyIdentifier.from_public_key(self._ca_key.public_key())
        builder = (
            x509.CertificateBuilder()
            .subject_name(self._x509_name(dn))
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(self._serial)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=DAYS))
        )
        if "server" in name:
            # the key identifiers are part of server_ext; the client
            # certificates never had them
            builder = (
                builder
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                               critical=False)
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
                    critical=False)
            )
        for ext, critical in self._extensions(name, dn, key.public_key()):
            builder = builder.add_extension(ext, critical=critical)
        cert = builder.sign(self._ca_key, hashes.SHA256())
        pem = cert.public_bytes(serialization.Encoding.PEM)
        self._write(f"certs/{name}.crt", pem)
        self._write(f"newcerts/{self._serial:02X}.pem", pem)
        # the "openssl ca" database: valid, expires, no revocation, serial,
        # file "unknown", subject
        self._index.append(
            f"V\t{_openssl_time(cert.not_valid_after_utc)}\t\t{self._serial:02X}"
            f"\tunknown\t{self._slash_dn(dn)}")
        self._serial += 1
        return cert

    def _make_proxy_cert(self, name: str, key) -> None:
        """Certificate and key in one file, proxy/<name>.pem (make_proxy_cert)."""
        crt = (self.dir / "certs" / f"{name}.crt").read_bytes()
        self._write(f"proxy/{name}.pem", crt + self._key_pem(key, False))

    def _revoke(self, name: str, cert: x509.Certificate, now: datetime.datetime,
                revoked: List[Tuple[x509.Certificate, datetime.datetime]]) -> None:
        # the database line of the certificate becomes an "R" line:
        # R, expires, revoked at, serial, file, subject
        for i, line in enumerate(self._index):
            fields = line.split("\t")
            if fields[3] == f"{cert.serial_number:02X}":
                fields[0] = "R"
                fields[2] = _openssl_time(now)
                self._index[i] = "\t".join(fields)
        revoked.append((cert, now))

    def _write_crl(self, now: datetime.datetime,
                   revoked: List[Tuple[x509.Certificate, datetime.datetime]]) -> None:
        ca_ski = x509.SubjectKeyIdentifier.from_public_key(self._ca_key.public_key())
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self._ca_cert.subject)
            .last_update(now).next_update(now + datetime.timedelta(days=DAYS))
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
                           critical=False)
            .add_extension(x509.CRLNumber(1), critical=False)
        )
        for cert, when in revoked:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(cert.serial_number).revocation_date(when).build())
        crl = builder.sign(self._ca_key, hashes.SHA256())
        self._write("crl/ca-bundle.crl", crl.public_bytes(serialization.Encoding.PEM))
        # SSLProxyCARevocationPath finds the CRL of an issuer by the hash of
        # the issuer's name: <hash>.r0
        link = self.dir / "crl" / f"{x509_name_hash(self._ca_cert.subject)}.r0"
        link.unlink(missing_ok=True)
        link.symlink_to("ca-bundle.crl")

    def generate(self) -> Path:
        """Build the full CA tree (idempotent). Returns the CA root dir."""
        if self.dir.is_dir() and (self.dir / "certs" / "ca.crt").exists():
            return self.root  # already generated
        now = (datetime.datetime.now(datetime.timezone.utc)
               .replace(microsecond=0) - datetime.timedelta(minutes=1))
        self._init_dirs()
        self._new_ca(now)
        revoked: List[Tuple[x509.Certificate, datetime.datetime]] = []
        for name in CERT_DN:
            key = self._new_key(name)
            cert = self._new_cert(name, key, now)
            if name.endswith("_revoked"):
                self._revoke(name, cert, now, revoked)
            if name.startswith("client_"):
                self._make_proxy_cert(name, key)
        # crl/ca-bundle.crl is referenced by SSLCARevocationFile
        self._write_crl(now, revoked)
        self._write("index.txt", ("\n".join(self._index) + "\n").encode())
        self._write("serial", f"{self._serial:02X}\n".encode())
        return self.root
