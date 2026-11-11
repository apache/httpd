import re

import pytest

from pyhttpd.conf import HttpdConf


class TestTLS13:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": "SSLProtocol TLSv1.3",
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def _configure_tls(self, env, protocol="TLSv1.3", ciphersuite=None):
        extras = f"SSLProtocol {protocol}\n"
        if ciphersuite:
            extras += f"SSLCipherSuite TLSv1.3 {ciphersuite}\n"
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": extras,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    # Single server-side cipher: server offers only TLS_AES_256_GCM_SHA384,
    # client connects without cipher restriction and must negotiate that cipher.
    def test_ssl_002_02_no_restriction_with_cipher(self, env):
        self._configure_tls(env, protocol="TLSv1.3",
                            ciphersuite="TLS_AES_256_GCM_SHA384")
        r = env.run(args=[
            'openssl', 's_client',
            '-connect', f'localhost:{env.https_port}',
            '-tls1_3',
        ], intext='')
        assert r.exit_code == 0, f"handshake failed: {r.stderr}"
        output = r.stdout + r.stderr
        assert 'TLS_AES_256_GCM_SHA384' in output, \
            f"expected TLS_AES_256_GCM_SHA384, got: {output}"

    # Single client-side cipher: server uses default ciphers, client restricts
    # to TLS_AES_256_GCM_SHA384 and must negotiate successfully with that cipher.
    def test_ssl_002_03_restricted_cipher_must_negotiate(self, env):
        self._configure_tls(env, protocol="TLSv1.3")
        r = env.run(args=[
            'openssl', 's_client',
            '-connect', f'localhost:{env.https_port}',
            '-tls1_3',
            '-ciphersuites', 'TLS_AES_256_GCM_SHA384',
        ], intext='')
        assert r.exit_code == 0, f"handshake failed: {r.stderr}"
        output = r.stdout + r.stderr
        assert 'TLS_AES_256_GCM_SHA384' in output, \
            f"expected TLS_AES_256_GCM_SHA384, got: {output}"

    # Cipher mismatch: server allows only TLS_CHACHA20_POLY1305_SHA256, client
    # sends only TLS_AES_256_GCM_SHA384.  The handshake must fail.
    def test_ssl_002_04_handshake_cipher_mismatch_must_fail(self, env):
        self._configure_tls(env, protocol="TLSv1.3",
                            ciphersuite="TLS_CHACHA20_POLY1305_SHA256")
        env.httpd_error_log.add_ignored_lognos(["AH10373"])
        env.httpd_error_log.add_ignored_matches([
            r'.*SSL Library Error.*',
        ])
        r = env.run(args=[
            'openssl', 's_client',
            '-connect', f'localhost:{env.https_port}',
            '-tls1_3',
            '-ciphersuites', 'TLS_AES_256_GCM_SHA384',
        ], intext='')
        output = r.stdout + r.stderr
        assert r.exit_code != 0 or 'handshake failure' in output.lower(), \
            f"expected handshake failure, got exit_code={r.exit_code}: {output}"

    # Version mismatch: server configured for TLSv1.3 only, client forces
    # TLSv1.2.  The handshake must fail.
    def test_ssl_002_05_protocal_mismatch_must_fail(self, env):
        self._configure_tls(env, protocol="-all +TLSv1.3")
        env.httpd_error_log.add_ignored_lognos(["AH10373"])
        env.httpd_error_log.add_ignored_matches([
            r'.*SSL Library Error.*',
        ])
        r = env.run(args=[
            'openssl', 's_client',
            '-connect', f'localhost:{env.https_port}',
            '-tls1_2',
        ], intext='')
        output = r.stdout + r.stderr
        assert r.exit_code != 0 or 'handshake failure' in output.lower() \
            or 'protocol version' in output.lower(), \
            f"expected handshake failure, got exit_code={r.exit_code}: {output}"
