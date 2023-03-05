import os

import pytest

from .conf import TlsTestConf


class TestProxyMachineCert:

    @pytest.fixture(autouse=True, scope='class')
    def clients_x(cls, env):
        return env.ca.get_first("clientsX")

    @pytest.fixture(autouse=True, scope='class')
    def clients_y(cls, env):
        return env.ca.get_first("clientsY")

    @pytest.fixture(autouse=True, scope='class')
    def cax_file(cls, clients_x):
        return os.path.join(os.path.dirname(clients_x.cert_file), "clientsX-ca.pem")

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(cls, env, cax_file, clients_x):
        # add vhosts a(tls)+b(ssl, port2) and a ssl proxy from a to b with a machine cert
        # host b requires a client certificate
        conf = TlsTestConf(env=env, extras={
            'base': [
                "LogLevel proxy:trace1 proxy_http:trace1 ssl:trace4 proxy_http2:trace1",
                "ProxyPreserveHost on",
                f"Listen {env.proxy_port}",
            ],
        })
        conf.start_tls_vhost(domains=[env.domain_a], port=env.https_port)
        conf.add([
            "Protocols h2 http/1.1",
            "TLSProxyEngine on",
            f"TLSProxyCA {env.ca.cert_file}",
            f"TLSProxyMachineCertificate {clients_x.get_first('user1').cert_file}",
            "<Location /proxy-tls/>",
            f"    ProxyPass https://127.0.0.1:{env.proxy_port}/",
            "</Location>",
        ])
        conf.end_tls_vhost()
        conf.start_vhost(domains=[env.domain_a], port=env.proxy_port,
                         doc_root=f"htdocs/{env.domain_a}", with_ssl=True)
        conf.add([
            "SSLVerifyClient require",
            "SSLVerifyDepth 2",
            "SSLOptions +StdEnvVars +ExportCertData",
            f"SSLCACertificateFile {cax_file}",
            "SSLUserName SSL_CLIENT_S_DN_CN"
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

    def test_tls_17_proxy_machine_cert_get_a(self, env):
        data = env.tls_get_json(env.domain_a, "/proxy-tls/index.json")
        assert data == {'domain': env.domain_a}

    @pytest.mark.parametrize("name, value", [
        ("SERVER_NAME", "a.mod-tls.test"),
        ("SSL_CLIENT_VERIFY", "SUCCESS"),
        ("REMOTE_USER", "user1"),
    ])
    def test_tls_17_proxy_machine_cert_vars(self, env, name: str, value: str):
        r = env.tls_get(env.domain_a, f"/proxy-tls/vars.py?name={name}")
        assert r.exit_code == 0, r.stderr
        assert r.json == {name: value}, r.stdout
