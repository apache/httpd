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

from cryptography import x509

SEC_PER_DAY = 24 * 60 * 60


log = logging.getLogger(__name__)


class MDCertUtil(object):
    # Utility class for inspecting certificates in test cases
    # Uses PyOpenSSL: https://pyopenssl.org/en/stable/index.html

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
        peer_cert = connection.get_peer_certificate()
        return MDCertUtil(None, cert=peer_cert)

    @classmethod
    def parse_pem_cert(cls, text):
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, text.encode('utf-8'))
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
        if cert_path is not None:
            self.cert_path = cert_path
            # load certificate and private key
            if cert_path.startswith("http"):
                cert_data = self.get_plain(cert_path, 1)
            else:
                cert_data = MDCertUtil._load_binary_file(cert_path)

            for file_type in (OpenSSL.crypto.FILETYPE_PEM, OpenSSL.crypto.FILETYPE_ASN1):
                try:
                    self.cert = OpenSSL.crypto.load_certificate(file_type, cert_data)
                except Exception as error:
                    self.error = error
        if cert is not None:
            self.cert = cert

        if self.cert is None:
            raise self.error

    def get_issuer(self):
        return self.cert.get_issuer()

    def get_serial(self):
        # the string representation of a serial number is not unique. Some
        # add leading 0s to align with word boundaries.
        return ("%lx" % (self.cert.get_serial_number())).upper()

    @staticmethod
    def _get_serial(cert) -> int:
        if isinstance(cert, x509.Certificate):
            return cert.serial_number
        if isinstance(cert, MDCertUtil):
            return cert.get_serial_number()
        elif isinstance(cert, OpenSSL.crypto.X509):
            return cert.get_serial_number()
        elif isinstance(cert, str):
            # assume a hex number
            return int(cert, 16)
        elif isinstance(cert, int):
            return cert
        return 0

    def get_serial_number(self):
        return self._get_serial(self.cert)

    def same_serial_as(self, other):
        return self._get_serial(self.cert) == self._get_serial(other)

    def get_not_before(self):
        tsp = self.cert.get_notBefore()
        return self._parse_tsp(tsp)

    def get_not_after(self):
        tsp = self.cert.get_notAfter()
        return self._parse_tsp(tsp)

    def get_cn(self):
        return self.cert.get_subject().CN

    def get_key_length(self):
        return self.cert.get_pubkey().bits()

    def get_san_list(self):
        text = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, self.cert).decode("utf-8")
        m = re.search(r"X509v3 Subject Alternative Name:(\s+critical)?\s*(.*)", text)
        sans_list = []
        if m:
            sans_list = m.group(2).split(",")

        def _strip_prefix(s):
            return s.split(":")[1] if s.strip().startswith("DNS:") else s.strip()
        return list(map(_strip_prefix, sans_list))

    def get_must_staple(self):
        text = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, self.cert).decode("utf-8")
        m = re.search(r"1.3.6.1.5.5.7.1.24:\s*\n\s*0....", text)
        if not m:
            # Newer openssl versions print this differently
            m = re.search(r"TLS Feature:\s*\n\s*status_request\s*\n", text)
        return m is not None

    @classmethod
    def validate_privkey(cls, privkey_path, passphrase=None):
        privkey_data = cls._load_binary_file(privkey_path)
        if passphrase:
            privkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, privkey_data, passphrase)
        else:
            privkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, privkey_data)
        return privkey.check()

    def validate_cert_matches_priv_key(self, privkey_path):
        # Verifies that the private key and cert match.
        privkey_data = MDCertUtil._load_binary_file(privkey_path)
        privkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, privkey_data)
        context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        context.use_privatekey(privkey)
        context.use_certificate(self.cert)
        context.check_privatekey()

    # --------- _utils_ ---------

    def astr(self, s):
        return s.decode('utf-8')
        
    def _parse_tsp(self, tsp):
        # timestampss returned by PyOpenSSL are bytes
        # parse date and time part
        s = ("%s-%s-%s %s:%s:%s" % (self.astr(tsp[0:4]), self.astr(tsp[4:6]), self.astr(tsp[6:8]),
                                    self.astr(tsp[8:10]), self.astr(tsp[10:12]), self.astr(tsp[12:14])))
        timestamp = datetime.strptime(s, '%Y-%m-%d %H:%M:%S')
        # adjust timezone
        tz_h, tz_m = 0, 0
        m = re.match(r"([+\-]\d{2})(\d{2})", self.astr(tsp[14:]))
        if m:
            tz_h, tz_m = int(m.group(1)),  int(m.group(2)) if tz_h > 0 else -1 * int(m.group(2))
        return timestamp.replace(tzinfo=self.FixedOffset(60 * tz_h + tz_m))

    @classmethod
    def _load_binary_file(cls, path):
        with open(path, mode="rb") as file:
            return file.read()

    class FixedOffset(tzinfo):

        def __init__(self, offset):
            self.__offset = timedelta(minutes=offset)

        def utcoffset(self, dt):
            return self.__offset

        def tzname(self, dt):
            return None

        def dst(self, dt):
            return timedelta(0)
