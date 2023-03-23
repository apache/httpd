import re
from datetime import timedelta

import pytest

from .conf import TlsTestConf


class TestProxyTLS:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        # add vhosts a+b and a ssl proxy from a to b
        conf = TlsTestConf(env=env, extras={
            'base': [
                "LogLevel proxy:trace1 proxy_http:trace1 proxy_http2:trace2 http2:trace2 cgid:trace4",
                "TLSProxyProtocol TLSv1.3+",
                f"<Proxy https://127.0.0.1:{env.https_port}/>",
                "    TLSProxyEngine on",
                f"    TLSProxyCA {env.ca.cert_file}",
                "    TLSProxyProtocol TLSv1.2+",
                "    TLSProxyCiphersPrefer TLS13_AES_256_GCM_SHA384",
                "    TLSProxyCiphersSuppress TLS13_AES_128_GCM_SHA256",
                "    ProxyPreserveHost on",
                "</Proxy>",
                f"<Proxy https://localhost:{env.https_port}/>",
                "    ProxyPreserveHost on",
                "</Proxy>",
                f"<Proxy h2://127.0.0.1:{env.https_port}/>",
                "    TLSProxyEngine on",
                f"    TLSProxyCA {env.ca.cert_file}",
                "    TLSProxyCiphersSuppress TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256",
                "    ProxyPreserveHost on",
                "</Proxy>",
            ],
            env.domain_b: [
                "Protocols h2 http/1.1",
                f"ProxyPass /proxy-tls/ https://127.0.0.1:{env.https_port}/",
                f"ProxyPass /proxy-local/ https://localhost:{env.https_port}/",
                f"ProxyPass /proxy-h2-tls/ h2://127.0.0.1:{env.https_port}/",
                "TLSOptions +StdEnvVars",
            ],
        })
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 0

    def test_tls_15_proxy_tls_get(self, env):
        data = env.tls_get_json(env.domain_b, "/proxy-tls/index.json")
        assert data == {'domain': env.domain_b}

    def test_tls_15_proxy_tls_get_local(self, env):
        # does not work, since SSLProxy* not configured
        data = env.tls_get_json(env.domain_b, "/proxy-local/index.json")
        assert data is None

    def test_tls_15_proxy_tls_h2_get(self, env):
        r = env.tls_get(env.domain_b, "/proxy-h2-tls/index.json")
        assert r.exit_code == 0
        assert r.json == {'domain': env.domain_b}, f"{r.stdout}"

    @pytest.mark.parametrize("name, value", [
        ("SERVER_NAME", "b.mod-tls.test"),
        ("SSL_PROTOCOL", "TLSv1.3"),
        ("SSL_CIPHER", "TLS_AES_256_GCM_SHA384"),
        ("SSL_SESSION_RESUMED", "Initial"),
        ("SSL_SECURE_RENEG", "false"),
        ("SSL_COMPRESS_METHOD", "NULL"),
        ("SSL_CIPHER_EXPORT", "false"),
        ("SSL_CLIENT_VERIFY", "NONE"),
    ])
    def test_tls_15_proxy_tls_h1_vars(self, env, name: str, value: str):
        r = env.tls_get(env.domain_b, f"/proxy-tls/vars.py?name={name}")
        assert r.exit_code == 0, r.stderr
        assert r.json == {name: value}, r.stdout

    @pytest.mark.parametrize("name, value", [
        ("SERVER_NAME", "b.mod-tls.test"),
        ("SSL_PROTOCOL", "TLSv1.3"),
        ("SSL_CIPHER", "TLS_CHACHA20_POLY1305_SHA256"),
        ("SSL_SESSION_RESUMED", "Initial"),
    ])
    def test_tls_15_proxy_tls_h2_vars(self, env, name: str, value: str):
        r = env.tls_get(env.domain_b, f"/proxy-h2-tls/vars.py?name={name}")
        assert r.exit_code == 0, r.stderr
        assert r.json == {name: value}, r.stdout
