import re
from datetime import timedelta

import pytest

from .env import TlsTestEnv
from .conf import TlsTestConf


class TestCiphers:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = TlsTestConf(env=env, extras={
            'base': "TLSHonorClientOrder off",
        })
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _function_scope(self, env):
        pass

    def _get_protocol_cipher(self, output: str):
        protocol = None
        cipher = None
        for line in output.splitlines():
            m = re.match(r'^\s+Protocol\s*:\s*(\S+)$', line)
            if m:
                protocol = m.group(1)
                continue
            m = re.match(r'^\s+Cipher\s*:\s*(\S+)$', line)
            if m:
                cipher = m.group(1)
        return protocol, cipher

    def test_tls_06_ciphers_ecdsa(self, env):
        ecdsa_1_2 = [c for c in env.RUSTLS_CIPHERS
                     if c.max_version == 1.2 and c.flavour == 'ECDSA'][0]
        # client speaks only this cipher, see that it gets it
        r = env.openssl_client(env.domain_b, extra_args=[
            "-cipher", ecdsa_1_2.openssl_name, "-tls1_2"
        ])
        protocol, cipher = self._get_protocol_cipher(r.stdout)
        assert protocol == "TLSv1.2", r.stdout
        assert cipher == ecdsa_1_2.openssl_name, r.stdout

    def test_tls_06_ciphers_rsa(self, env):
        rsa_1_2 = [c for c in env.RUSTLS_CIPHERS
                   if c.max_version == 1.2 and c.flavour == 'RSA'][0]
        # client speaks only this cipher, see that it gets it
        r = env.openssl_client(env.domain_b, extra_args=[
            "-cipher", rsa_1_2.openssl_name, "-tls1_2"
        ])
        protocol, cipher = self._get_protocol_cipher(r.stdout)
        assert protocol == "TLSv1.2", r.stdout
        assert cipher == rsa_1_2.openssl_name, r.stdout

    @pytest.mark.parametrize("cipher", [
        c for c in TlsTestEnv.RUSTLS_CIPHERS if c.max_version == 1.2 and c.flavour == 'ECDSA'
    ], ids=[
        c.name for c in TlsTestEnv.RUSTLS_CIPHERS if c.max_version == 1.2 and c.flavour == 'ECDSA'
    ])
    def test_tls_06_ciphers_server_prefer_ecdsa(self, env, cipher):
        # Select a ECSDA ciphers as preference and suppress all RSA ciphers.
        # The last is not strictly necessary since rustls prefers ECSDA anyway
        suppress_names = [c.name for c in env.RUSTLS_CIPHERS
                          if c.max_version == 1.2 and c.flavour == 'RSA']
        conf = TlsTestConf(env=env, extras={
            env.domain_b: [
                "TLSHonorClientOrder off",
                f"TLSCiphersPrefer {cipher.name}",
                f"TLSCiphersSuppress {':'.join(suppress_names)}",
            ]
        })
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 0
        r = env.openssl_client(env.domain_b, extra_args=["-tls1_2"])
        client_proto, client_cipher = self._get_protocol_cipher(r.stdout)
        assert client_proto == "TLSv1.2", r.stdout
        assert client_cipher == cipher.openssl_name, r.stdout

    @pytest.mark.skip(reason="Wrong certified key selected by rustls")
    # see <https://github.com/rustls/rustls-ffi/issues/236>
    @pytest.mark.parametrize("cipher", [
        c for c in TlsTestEnv.RUSTLS_CIPHERS if c.max_version == 1.2 and c.flavour == 'RSA'
    ], ids=[
        c.name for c in TlsTestEnv.RUSTLS_CIPHERS if c.max_version == 1.2 and c.flavour == 'RSA'
    ])
    def test_tls_06_ciphers_server_prefer_rsa(self, env, cipher):
        # Select a RSA ciphers as preference and suppress all ECDSA ciphers.
        # The last is necessary since rustls prefers ECSDA and openssl leaks that it can.
        suppress_names = [c.name for c in env.RUSTLS_CIPHERS
                          if c.max_version == 1.2 and c.flavour == 'ECDSA']
        conf = TlsTestConf(env=env, extras={
            env.domain_b: [
                "TLSHonorClientOrder off",
                f"TLSCiphersPrefer {cipher.name}",
                f"TLSCiphersSuppress {':'.join(suppress_names)}",
            ]
        })
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 0
        r = env.openssl_client(env.domain_b, extra_args=["-tls1_2"])
        client_proto, client_cipher = self._get_protocol_cipher(r.stdout)
        assert client_proto == "TLSv1.2", r.stdout
        assert client_cipher == cipher.openssl_name, r.stdout

    @pytest.mark.skip(reason="Wrong certified key selected by rustls")
    # see <https://github.com/rustls/rustls-ffi/issues/236>
    @pytest.mark.parametrize("cipher", [
        c for c in TlsTestEnv.RUSTLS_CIPHERS if c.max_version == 1.2 and c.flavour == 'RSA'
    ], ids=[
        c.openssl_name for c in TlsTestEnv.RUSTLS_CIPHERS if c.max_version == 1.2 and c.flavour == 'RSA'
    ])
    def test_tls_06_ciphers_server_prefer_rsa_alias(self, env, cipher):
        # same as above, but using openssl names for ciphers
        suppress_names = [c.openssl_name for c in env.RUSTLS_CIPHERS
                          if c.max_version == 1.2 and c.flavour == 'ECDSA']
        conf = TlsTestConf(env=env, extras={
            env.domain_b: [
                "TLSHonorClientOrder off",
                f"TLSCiphersPrefer {cipher.openssl_name}",
                f"TLSCiphersSuppress {':'.join(suppress_names)}",
            ]
        })
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 0
        r = env.openssl_client(env.domain_b, extra_args=["-tls1_2"])
        client_proto, client_cipher = self._get_protocol_cipher(r.stdout)
        assert client_proto == "TLSv1.2", r.stdout
        assert client_cipher == cipher.openssl_name, r.stdout

    @pytest.mark.skip(reason="Wrong certified key selected by rustls")
    # see <https://github.com/rustls/rustls-ffi/issues/236>
    @pytest.mark.parametrize("cipher", [
        c for c in TlsTestEnv.RUSTLS_CIPHERS if c.max_version == 1.2 and c.flavour == 'RSA'
    ], ids=[
        c.id_name for c in TlsTestEnv.RUSTLS_CIPHERS if c.max_version == 1.2 and c.flavour == 'RSA'
    ])
    def test_tls_06_ciphers_server_prefer_rsa_id(self, env, cipher):
        # same as above, but using openssl names for ciphers
        suppress_names = [c.id_name for c in env.RUSTLS_CIPHERS
                          if c.max_version == 1.2 and c.flavour == 'ECDSA']
        conf = TlsTestConf(env=env, extras={
            env.domain_b: [
                "TLSHonorClientOrder off",
                f"TLSCiphersPrefer {cipher.id_name}",
                f"TLSCiphersSuppress {':'.join(suppress_names)}",
            ]
        })
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 0
        r = env.openssl_client(env.domain_b, extra_args=["-tls1_2"])
        client_proto, client_cipher = self._get_protocol_cipher(r.stdout)
        assert client_proto == "TLSv1.2", r.stdout
        assert client_cipher == cipher.openssl_name, r.stdout

    def test_tls_06_ciphers_pref_unknown(self, env):
        conf = TlsTestConf(env=env, extras={
            env.domain_b: "TLSCiphersPrefer TLS_MY_SUPER_CIPHER:SSL_WHAT_NOT"
        })
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() != 0
        # get a working config again, so that subsequent test cases do not stumble
        conf = TlsTestConf(env=env)
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        env.apache_restart()

    def test_tls_06_ciphers_pref_unsupported(self, env):
        # a warning on preferring a known, but not supported cipher
        env.httpd_error_log.ignore_recent()
        conf = TlsTestConf(env=env, extras={
            env.domain_b: "TLSCiphersPrefer TLS_NULL_WITH_NULL_NULL"
        })
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 0
        (errors, warnings) = env.httpd_error_log.get_recent_count()
        assert errors == 0
        assert warnings == 2  # once on dry run, once on start

    def test_tls_06_ciphers_supp_unknown(self, env):
        conf = TlsTestConf(env=env, extras={
            env.domain_b: "TLSCiphersSuppress TLS_MY_SUPER_CIPHER:SSL_WHAT_NOT"
        })
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() != 0

    def test_tls_06_ciphers_supp_unsupported(self, env):
        # no warnings on suppressing known, but not supported ciphers
        env.httpd_error_log.ignore_recent()
        conf = TlsTestConf(env=env, extras={
            env.domain_b: "TLSCiphersSuppress TLS_NULL_WITH_NULL_NULL"
        })
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 0
        (errors, warnings) = env.httpd_error_log.get_recent_count()
        assert errors == 0
        assert warnings == 0
