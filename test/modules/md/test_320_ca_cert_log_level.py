"""mod_md's curl-based HTTP client only logged the specific reason a request
to the ACME server failed (e.g. "Problem with the SSL CA cert (path? access
rights?)") at debug level. At a normal production LogLevel this reason was
invisible, and the error an administrator actually saw was the generic
"Internal error (specific information not available)" wrapper (BZ 70300).

This does not need a real ACME server: a bad MDCACertificateFile fails
before any ACME-specific request is made, against any HTTPS endpoint.
"""
import datetime
import os
import re
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .md_conf import MDConf
from .md_env import MDTestEnv


def _make_self_signed_cert(cert_path, pkey_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(pkey_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))


class _DirectoryHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class TestCACertLogLevel:

    @pytest.fixture(scope='class')
    def fake_acme_port(self, env):
        cert_file = os.path.join(env.gen_dir, "md-320-fake-acme.crt")
        pkey_file = os.path.join(env.gen_dir, "md-320-fake-acme.key")
        _make_self_signed_cert(cert_file, pkey_file)

        server = HTTPServer(("127.0.0.1", 0), _DirectoryHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_file, keyfile=pkey_file)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        yield port
        server.shutdown()

    def test_md_320_01_ca_cert_error_visible_at_warn_level(self, env, request, fake_acme_port):
        """A bad MDCACertificateFile must be reported at a level visible
        with a normal LogLevel, not only with md:debug/trace4."""
        domain = env.get_request_domain(request)
        bad_ca_file = os.path.join(env.gen_dir, "md-320-does-not-exist-ca-bundle.crt")
        assert not os.path.exists(bad_ca_file)

        conf = MDConf(env, local_ca=False)
        conf.add([
            "LogLevel md:warn",
            f"MDCACertificateFile {bad_ca_file}",
            f"MDCertificateAuthority https://127.0.0.1:{fake_acme_port}/directory",
            "MDCertificateAgreement accepted",
            f"MDomain {domain}",
        ])
        conf.add_vhost(domains=[domain], port=env.https_port, with_ssl=True)
        conf.install()
        assert env.apache_restart() == 0

        start = env.httpd_error_log.current_pos()
        line = env.httpd_error_log.wait_for(
            re.compile(r'.*\[md:error\].*Problem with the SSL CA cert.*'),
            start, timeout=15)
        assert line, (
            "expected the specific curl CA-cert error to be logged at "
            "md:error, not only at md:debug/trace4")
        env.httpd_error_log.ignore_recent(matches=[
            r'.*Problem with the SSL CA cert.*',
            r'.*Unsuccessful in contacting ACME server.*',
            r'.*AH10056.*',
        ])
