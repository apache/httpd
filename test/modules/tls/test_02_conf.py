import os
from datetime import timedelta

import pytest

from .conf import TlsTestConf


class TestConf:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        TlsTestConf(env=env).install()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _function_scope(self, env):
        if env.is_live(timeout=timedelta(milliseconds=100)):
            assert env.apache_stop() == 0

    def test_tls_02_conf_cert_args_missing(self, env):
        conf = TlsTestConf(env=env)
        conf.add("TLSCertificate")
        conf.install()
        assert env.apache_fail() == 0

    def test_tls_02_conf_cert_single_arg(self, env):
        conf = TlsTestConf(env=env)
        conf.add("TLSCertificate cert.pem")
        conf.install()
        assert env.apache_fail() == 0

    def test_tls_02_conf_cert_file_missing(self, env):
        conf = TlsTestConf(env=env)
        conf.add("TLSCertificate cert.pem key.pem")
        conf.install()
        assert env.apache_fail() == 0

    def test_tls_02_conf_cert_file_exist(self, env):
        conf = TlsTestConf(env=env)
        conf.add("TLSCertificate test-02-cert.pem test-02-key.pem")
        conf.install()
        for name in ["test-02-cert.pem", "test-02-key.pem"]:
            with open(os.path.join(env.server_dir, name), "w") as fd:
                fd.write("")
        assert env.apache_fail() == 0

    def test_tls_02_conf_cert_listen_missing(self, env):
        conf = TlsTestConf(env=env)
        conf.add("TLSEngine")
        conf.install()
        assert env.apache_fail() == 0

    def test_tls_02_conf_cert_listen_wrong(self, env):
        conf = TlsTestConf(env=env)
        conf.add("TLSEngine ^^^^^")
        conf.install()
        assert env.apache_fail() == 0

    @pytest.mark.parametrize("listen", [
        "443",
        "129.168.178.188:443",
        "[::]:443",
    ])
    def test_tls_02_conf_cert_listen_valid(self, env, listen: str):
        conf = TlsTestConf(env=env)
        conf.add("TLSEngine {listen}".format(listen=listen))
        conf.install()
        assert env.apache_restart() == 0

    def test_tls_02_conf_cert_listen_cert(self, env):
        domain = env.domain_a
        conf = TlsTestConf(env=env)
        conf.add_tls_vhosts(domains=[domain])
        conf.install()
        assert env.apache_restart() == 0

    def test_tls_02_conf_proto_wrong(self, env):
        conf = TlsTestConf(env=env)
        conf.add("TLSProtocol wrong")
        conf.install()
        assert env.apache_fail() == 0

    @pytest.mark.parametrize("proto", [
        "default",
        "TLSv1.2+",
        "TLSv1.3+",
        "TLSv0x0303+",
    ])
    def test_tls_02_conf_proto_valid(self, env, proto):
        conf = TlsTestConf(env=env)
        conf.add("TLSProtocol {proto}".format(proto=proto))
        conf.install()
        assert env.apache_restart() == 0

    def test_tls_02_conf_honor_wrong(self, env):
        conf = TlsTestConf(env=env)
        conf.add("TLSHonorClientOrder wrong")
        conf.install()
        assert env.apache_fail() == 0

    @pytest.mark.parametrize("honor", [
        "on",
        "OfF",
    ])
    def test_tls_02_conf_honor_valid(self, env, honor: str):
        conf = TlsTestConf(env=env)
        conf.add("TLSHonorClientOrder {honor}".format(honor=honor))
        conf.install()
        assert env.apache_restart() == 0

    @pytest.mark.parametrize("cipher", [
        "default",
        "TLS13_AES_128_GCM_SHA256:TLS13_AES_256_GCM_SHA384:TLS13_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        """TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 \\
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\\
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"""
    ])
    def test_tls_02_conf_cipher_valid(self, env, cipher):
        conf = TlsTestConf(env=env)
        conf.add("TLSCiphersPrefer {cipher}".format(cipher=cipher))
        conf.install()
        assert env.apache_restart() == 0

    @pytest.mark.parametrize("cipher", [
        "wrong",
        "YOLO",
        "TLS_NULL_WITH_NULL_NULLX",       # not supported
        "TLS_DHE_RSA_WITH_AES128_GCM_SHA256",     # not supported
    ])
    def test_tls_02_conf_cipher_wrong(self, env, cipher):
        conf = TlsTestConf(env=env)
        conf.add("TLSCiphersPrefer {cipher}".format(cipher=cipher))
        conf.install()
        assert env.apache_fail() == 0
