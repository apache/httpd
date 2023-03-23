import re
import pytest

from .conf import TlsTestConf


class TestProxySSL:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        # add vhosts a+b and a ssl proxy from a to b
        conf = TlsTestConf(env=env, extras={
            'base': [
                "LogLevel proxy:trace1 proxy_http:trace1 ssl:trace1 proxy_http2:trace1",
                f"<Proxy https://127.0.0.1:{env.https_port}/>",
                "    SSLProxyEngine on",
                "    SSLProxyVerify require",
                f"    SSLProxyCACertificateFile {env.ca.cert_file}",
                "  ProxyPreserveHost on",
                "</Proxy>",
                f"<Proxy https://localhost:{env.https_port}/>",
                "    ProxyPreserveHost on",
                "</Proxy>",
                f"<Proxy h2://127.0.0.1:{env.https_port}/>",
                "    SSLProxyEngine on",
                "    SSLProxyVerify require",
                f"    SSLProxyCACertificateFile {env.ca.cert_file}",
                "    ProxyPreserveHost on",
                "</Proxy>",
                ],
            env.domain_b: [
                "Protocols h2 http/1.1",
                f'ProxyPass /proxy-ssl/ https://127.0.0.1:{env.https_port}/',
                f'ProxyPass /proxy-local/ https://localhost:{env.https_port}/',
                f'ProxyPass /proxy-h2-ssl/ h2://127.0.0.1:{env.https_port}/',
                "TLSOptions +StdEnvVars",
            ],
        })
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 0

    def test_tls_14_proxy_ssl_get(self, env):
        data = env.tls_get_json(env.domain_b, "/proxy-ssl/index.json")
        assert data == {'domain': env.domain_b}

    def test_tls_14_proxy_ssl_get_local(self, env):
        # does not work, since SSLProxy* not configured
        data = env.tls_get_json(env.domain_b, "/proxy-local/index.json")
        assert data is None

    def test_tls_14_proxy_ssl_h2_get(self, env):
        r = env.tls_get(env.domain_b, "/proxy-h2-ssl/index.json")
        assert r.exit_code == 0
        assert r.json == {'domain': env.domain_b}

    @pytest.mark.parametrize("name, value", [
        ("SERVER_NAME", "b.mod-tls.test"),
        ("SSL_SESSION_RESUMED", "Initial"),
        ("SSL_SECURE_RENEG", "false"),
        ("SSL_COMPRESS_METHOD", "NULL"),
        ("SSL_CIPHER_EXPORT", "false"),
        ("SSL_CLIENT_VERIFY", "NONE"),
    ])
    def test_tls_14_proxy_ssl_vars_const(self, env, name: str, value: str):
        r = env.tls_get(env.domain_b, f"/proxy-ssl/vars.py?name={name}")
        assert r.exit_code == 0, r.stderr
        assert r.json == {name: value}, r.stdout

    @pytest.mark.parametrize("name, pattern", [
        ("SSL_VERSION_INTERFACE", r'mod_tls/\d+\.\d+\.\d+'),
        ("SSL_VERSION_LIBRARY", r'rustls-ffi/\d+\.\d+\.\d+/rustls/\d+\.\d+\.\d+'),
    ])
    def test_tls_14_proxy_ssl_vars_match(self, env, name: str, pattern: str):
        r = env.tls_get(env.domain_b, f"/proxy-ssl/vars.py?name={name}")
        assert r.exit_code == 0, r.stderr
        assert name in r.json
        assert re.match(pattern, r.json[name]), r.json
