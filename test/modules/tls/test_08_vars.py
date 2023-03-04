import re

import pytest

from .conf import TlsTestConf
from .env import TlsTestEnv


class TestVars:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = TlsTestConf(env=env, extras={
            'base': [
                "TLSHonorClientOrder off",
                "TLSOptions +StdEnvVars",
            ]
        })
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 0

    def test_tls_08_vars_root(self, env):
        # in domain_b root, the StdEnvVars is switch on
        exp_proto = "TLSv1.2"
        exp_cipher = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
        options = [ '--tls-max', '1.2']
        r = env.tls_get(env.domain_b, "/vars.py", options=options)
        assert r.exit_code == 0, r.stderr
        assert r.json == {
            'https': 'on',
            'host': 'b.mod-tls.test',
            'protocol': 'HTTP/1.1',
            'ssl_protocol': exp_proto,
            # this will vary by client potentially
            'ssl_cipher': exp_cipher,
        }

    @pytest.mark.parametrize("name, value", [
        ("SERVER_NAME", "b.mod-tls.test"),
        ("SSL_SESSION_RESUMED", "Initial"),
        ("SSL_SECURE_RENEG", "false"),
        ("SSL_COMPRESS_METHOD", "NULL"),
        ("SSL_CIPHER_EXPORT", "false"),
        ("SSL_CLIENT_VERIFY", "NONE"),
    ])
    def test_tls_08_vars_const(self, env, name: str, value: str):
        r = env.tls_get(env.domain_b, f"/vars.py?name={name}")
        assert r.exit_code == 0, r.stderr
        assert r.json == {name: value}, r.stdout

    @pytest.mark.parametrize("name, pattern", [
        ("SSL_VERSION_INTERFACE", r'mod_tls/\d+\.\d+\.\d+'),
        ("SSL_VERSION_LIBRARY", r'rustls-ffi/\d+\.\d+\.\d+/rustls/\d+\.\d+\.\d+'),
    ])
    def test_tls_08_vars_match(self, env, name: str, pattern: str):
        r = env.tls_get(env.domain_b, f"/vars.py?name={name}")
        assert r.exit_code == 0, r.stderr
        assert name in r.json
        assert re.match(pattern, r.json[name]), r.json
