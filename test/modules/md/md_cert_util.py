import logging
import re
import socket
import OpenSSL
import time
import sys

from datetime import datetime
from datetime import tzinfo
from datetime import timedelta
from http.client import HTTPConnection
from urllib.parse import urlparse

from cryptography.hazmat._oid import ExtensionOID
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, load_pem_private_key

from cryptography import x509
from cryptography.x509 import DNSName, ExtensionNotFound

SEC_PER_DAY = 24 * 60 * 60


log = logging.getLogger(__name__)


class MDCertUtil(object):
    # Utility class for inspecting certificates in test cases

    @classmethod
    def load_server_cert(cls, host_ip, host_port, host_name, tls=None, ciphers=None):
        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        if tls is not None and tls != 1.0:
            ctx.set_options(OpenSSL.SSL.OP_NO_TLSv1)
        if tls is not None and tls != 1.1:
            ctx.set_options(OpenSSL.SSL.OP_NO_TLSv1_1)
        if tls is not None and tls != 1.2:
            ctx.set_options(OpenSSL.SSL.OP_NO_TLSv1_2)
        if tls is not None and tls != 1.3 and hasattr(OpenSSL.SSL, "OP_NO_TLSv1_3"):
            ctx.set_options(OpenSSL.SSL.OP_NO_TLSv1_3)
        if ciphers is not None:
            ctx.set_cipher_list(ciphers)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection = OpenSSL.SSL.Connection(ctx, s)
        connection.connect((host_ip, int(host_port)))
        connection.setblocking(1)
        connection.set_tlsext_host_name(host_name.encode('utf-8'))
        connection.do_handshake()
        ossl_cert = connection.get_peer_certificate()
        return MDCertUtil(None, cert=ossl_cert.to_cryptography())

    @classmethod
    def parse_pem_cert(cls, text):
        cert = x509.load_pem_x509_certificate(text.encode('utf-8'))
        return MDCertUtil(None, cert=cert)

    @classmethod
    def get_plain(cls, url, timeout):
        server = urlparse(url)
        try_until = time.time() + timeout
        while time.time() < try_until:
            # noinspection PyBroadException
            try:
                c = HTTPConnection(server.hostname, server.port, timeout=timeout)
                c.request('GET', server.path)
                resp = c.getresponse()
                data = resp.read()
                c.close()
                return data
            except IOError:
                log.debug("connect error:", sys.exc_info()[0])
                time.sleep(.1)
            except:
                log.error("Unexpected error:", sys.exc_info()[0])
        log.error("Unable to contact server after %d sec" % timeout)
        return None

    def __init__(self, cert_path, cert=None):
        self.cert = cert
        self.privkey = None
        if cert_path is not None:
            self.cert_path = cert_path
            # load certificate and private key
            if cert_path.startswith("http"):
                assert False
            try:
                with open(cert_path) as fd:
                    cert = x509.load_pem_x509_certificate("".join(fd.readlines()).encode())
            except Exception as error:
                self.error = error
            if cert is not None:
                self.cert = cert
            if self.cert is None:
                raise self.error

    def add_privkey(self, path, password=None):
        with open(path) as fd:
            self.privkey = load_pem_private_key("".join(fd.readlines()).encode(), password=password)

    def get_issuer(self):
        return self.cert.get_issuer()

    def get_serial(self):
        # the string representation of a serial number is not unique. Some
        # add leading 0s to align with word boundaries.
        return ("%lx" % (self.cert.serial_number)).upper()

    @staticmethod
    def _get_serial(cert) -> int:
        if isinstance(cert, x509.Certificate):
            return cert.serial_number
        if isinstance(cert, MDCertUtil):
            return cert.cert.serial_number
        elif isinstance(cert, str):
            # assume a hex number
            return int(cert, 16)
        elif isinstance(cert, int):
            return cert
        assert False, f'{cert}'
        return 0

    def get_serial_number(self):
        return self._get_serial(self.cert)

    def same_serial_as(self, other):
        return self._get_serial(self.cert) == self._get_serial(other)

    def get_not_before(self):
        try:
            return self.cert.not_valid_before_utc
        except AttributeError:
            return self.cert.not_valid_before

    def get_not_after(self):
        try:
            return self.cert.not_valid_after_utc
        except AttributeError:
            return self.cert.not_valid_after

    def get_key_length(self):
        return self.cert.public_key().key_size

    def get_san_list(self):
        sans = self.cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return sans.value.get_values_for_type(DNSName)

    def get_must_staple(self):
        try:
            self.cert.extensions.get_extension_for_oid(ExtensionOID.TLS_FEATURE)
            return True
        except ExtensionNotFound:
            return False

    @classmethod
    def validate_privkey(cls, privkey_path, passphrase=None):
        with open(privkey_path) as fd:
            privkey = load_pem_private_key("".join(fd.readlines()).encode(), password=passphrase)
            return privkey is not None
