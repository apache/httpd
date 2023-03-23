import time

import pytest

from .conf import TlsTestConf


class TestProxyMixed:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = TlsTestConf(env=env, extras={
            'base': [
                "LogLevel proxy:trace1 proxy_http:trace1 ssl:trace1 proxy_http2:trace1 http2:debug",
                "ProxyPreserveHost on",
            ],
            env.domain_a: [
                "Protocols h2 http/1.1",
                "TLSProxyEngine on",
                f"TLSProxyCA {env.ca.cert_file}",
                "<Location /proxy-tls/>",
                f"    ProxyPass h2://127.0.0.1:{env.https_port}/",
                "</Location>",
            ],
            env.domain_b: [
                "SSLProxyEngine on",
                "SSLProxyVerify require",
                f"SSLProxyCACertificateFile {env.ca.cert_file}",
                "<Location /proxy-ssl/>",
                f"    ProxyPass https://127.0.0.1:{env.https_port}/",
                "</Location>",
            ],
        })
        # add vhosts a+b and a ssl proxy from a to b
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 0

    def test_tls_16_proxy_mixed_ssl_get(self, env, repeat):
        data = env.tls_get_json(env.domain_b, "/proxy-ssl/index.json")
        assert data == {'domain': env.domain_b}

    def test_tls_16_proxy_mixed_tls_get(self, env, repeat):
        data = env.tls_get_json(env.domain_a, "/proxy-tls/index.json")
        if data is None:
            time.sleep(300)
        assert data == {'domain': env.domain_a}
