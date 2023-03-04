from datetime import timedelta

import pytest

from .conf import TlsTestConf


class TestProxy:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = TlsTestConf(env=env, extras={
            'base': "LogLevel proxy:trace1 proxy_http:trace1 ssl:trace1",
            env.domain_b: [
                "ProxyPreserveHost on",
                f'ProxyPass "/proxy/" "http://127.0.0.1:{env.http_port}/"',
                f'ProxyPassReverse "/proxy/" "http://{env.domain_b}:{env.http_port}"',
            ]
        })
        # add vhosts a+b and a ssl proxy from a to b
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 0

    def test_tls_13_proxy_http_get(self, env):
        data = env.tls_get_json(env.domain_b, "/proxy/index.json")
        assert data == {'domain': env.domain_b}

    @pytest.mark.parametrize("name, value", [
        ("SERVER_NAME", "b.mod-tls.test"),
        ("SSL_SESSION_RESUMED", ""),
        ("SSL_SECURE_RENEG", ""),
        ("SSL_COMPRESS_METHOD", ""),
        ("SSL_CIPHER_EXPORT", ""),
        ("SSL_CLIENT_VERIFY", ""),
    ])
    def test_tls_13_proxy_http_vars(self, env, name: str, value: str):
        r = env.tls_get(env.domain_b, f"/proxy/vars.py?name={name}")
        assert r.exit_code == 0, r.stderr
        assert r.json == {name: value}, r.stdout
