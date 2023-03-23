import os
from datetime import timedelta
from typing import Optional

import pytest

from pyhttpd.certs import Credentials
from .conf import TlsTestConf


@pytest.fixture
def clients_x(env):
    return env.ca.get_first("clientsX")


@pytest.fixture
def clients_y(env):
    return env.ca.get_first("clientsY")


@pytest.fixture
def cax_file(clients_x):
    return os.path.join(os.path.dirname(clients_x.cert_file), "clientX-ca.pem")


@pytest.mark.skip(reason="client certs disabled")
class TestTLS:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, clients_x, cax_file):
        with open(cax_file, 'w') as fd:
            fd.write("".join(open(clients_x.cert_file).readlines()))
            fd.write("".join(open(env.ca.cert_file).readlines()))

    @pytest.fixture(autouse=True, scope='function')
    def _function_scope(self, env):
        if env.is_live(timeout=timedelta(milliseconds=100)):
            assert env.apache_stop() == 0

    def get_ssl_var(self, env, domain: str, cert: Optional[Credentials], name: str):
        r = env.tls_get(domain, f"/vars.py?name={name}", options=[
            "--cert", cert.cert_file
        ] if cert else [])
        assert r.exit_code == 0, r.stderr
        assert r.json, r.stderr + r.stdout
        return r.json[name] if name in r.json else None

    def test_tls_12_set_ca_non_existing(self, env):
        conf = TlsTestConf(env=env, extras={
            env.domain_a: "TLSClientCA xxx"
        })
        conf.add_md_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 1

    def test_tls_12_set_ca_existing(self, env, cax_file):
        conf = TlsTestConf(env=env, extras={
            env.domain_a: f"TLSClientCA {cax_file}"
        })
        conf.add_md_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 0

    def test_tls_12_set_auth_no_ca(self, env):
        conf = TlsTestConf(env=env, extras={
            env.domain_a: "TLSClientCertificate required"
        })
        conf.add_md_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        # will fail bc lacking clien CA
        assert env.apache_restart() == 1

    def test_tls_12_auth_option_std(self, env, cax_file, clients_x):
        conf = TlsTestConf(env=env, extras={
            env.domain_b: [
                f"TLSClientCertificate required",
                f"TLSClientCA {cax_file}",
                "# TODO: TLSUserName SSL_CLIENT_S_DN_CN",
                "TLSOptions +StdEnvVars",
            ]
        })
        conf.add_md_vhosts(domains=[env.domain_b])
        conf.install()
        assert env.apache_restart() == 0
        # should be denied
        r = env.tls_get(domain=env.domain_b, paths="/index.json")
        assert r.exit_code != 0, r.stdout
        # should work
        ccert = clients_x.get_first("user1")
        data = env.tls_get_json(env.domain_b, "/index.json", options=[
            "--cert", ccert.cert_file
        ])
        assert data == {'domain': env.domain_b}
        r = env.tls_get(env.domain_b, "/vars.py?name=SSL_CLIENT_S_DN_CN")
        assert r.exit_code != 0, "should have been prevented"
        val = self.get_ssl_var(env, env.domain_b, ccert, "SSL_CLIENT_S_DN_CN")
        assert val == 'Not Implemented'
        # TODO
        # val = self.get_ssl_var(env, env.domain_b, ccert, "REMOTE_USER")
        # assert val == 'Not Implemented'
        # not set on StdEnvVars, needs option ExportCertData
        val = self.get_ssl_var(env, env.domain_b, ccert, "SSL_CLIENT_CERT")
        assert val == ""

    def test_tls_12_auth_option_cert(self, env, test_ca, cax_file, clients_x):
        conf = TlsTestConf(env=env, extras={
            env.domain_b: [
                "TLSClientCertificate required",
                f"TLSClientCA {cax_file}",
                "TLSOptions Defaults +ExportCertData",
            ]
        })
        conf.add_md_vhosts(domains=[env.domain_b])
        conf.install()
        assert env.apache_restart() == 0
        ccert = clients_x.get_first("user1")
        val = self.get_ssl_var(env, env.domain_b, ccert, "SSL_CLIENT_CERT")
        assert val == ccert.cert_pem.decode()
        # no chain should be present
        val = self.get_ssl_var(env, env.domain_b, ccert, "SSL_CLIENT_CHAIN_0")
        assert val == ''
        val = self.get_ssl_var(env, env.domain_b, ccert, "SSL_SERVER_CERT")
        assert val
        server_certs = test_ca.get_credentials_for_name(env.domain_b)
        assert val in [c.cert_pem.decode() for c in server_certs]

    def test_tls_12_auth_ssl_optional(self, env, cax_file, clients_x):
        domain = env.domain_b
        conf = TlsTestConf(env=env, extras={
            domain: [
                "SSLVerifyClient optional",
                "SSLVerifyDepth 2",
                "SSLOptions +StdEnvVars +ExportCertData",
                f"SSLCACertificateFile {cax_file}",
                "SSLUserName SSL_CLIENT_S_DN",
            ]
        })
        conf.add_ssl_vhosts(domains=[domain])
        conf.install()
        assert env.apache_restart() == 0
        # should work either way
        data = env.tls_get_json(domain, "/index.json")
        assert data == {'domain': domain}
        # no client cert given, we expect the server variable to be empty
        val = self.get_ssl_var(env, env.domain_b, None, "SSL_CLIENT_S_DN_CN")
        assert val == ''
        ccert = clients_x.get_first("user1")
        data = env.tls_get_json(domain, "/index.json", options=[
            "--cert", ccert.cert_file
        ])
        assert data == {'domain': domain}
        val = self.get_ssl_var(env, env.domain_b, ccert, "SSL_CLIENT_S_DN_CN")
        assert val == 'user1'
        val = self.get_ssl_var(env, env.domain_b, ccert, "SSL_CLIENT_S_DN")
        assert val == 'O=abetterinternet-mod_tls,OU=clientsX,CN=user1'
        val = self.get_ssl_var(env, env.domain_b, ccert, "REMOTE_USER")
        assert val == 'O=abetterinternet-mod_tls,OU=clientsX,CN=user1'
        val = self.get_ssl_var(env, env.domain_b, ccert, "SSL_CLIENT_I_DN")
        assert val == 'O=abetterinternet-mod_tls,OU=clientsX'
        val = self.get_ssl_var(env, env.domain_b, ccert, "SSL_CLIENT_I_DN_CN")
        assert val == ''
        val = self.get_ssl_var(env, env.domain_b, ccert, "SSL_CLIENT_I_DN_OU")
        assert val == 'clientsX'
        val = self.get_ssl_var(env, env.domain_b, ccert, "SSL_CLIENT_CERT")
        assert val == ccert.cert_pem.decode()

    def test_tls_12_auth_optional(self, env, cax_file, clients_x):
        domain = env.domain_b
        conf = TlsTestConf(env=env, extras={
            domain: [
                "TLSClientCertificate optional",
                f"TLSClientCA {cax_file}",
            ]
        })
        conf.add_md_vhosts(domains=[domain])
        conf.install()
        assert env.apache_restart() == 0
        # should work either way
        data = env.tls_get_json(domain, "/index.json")
        assert data == {'domain': domain}
        # no client cert given, we expect the server variable to be empty
        r = env.tls_get(domain, "/vars.py?name=SSL_CLIENT_S_DN_CN")
        assert r.exit_code == 0, r.stderr
        assert r.json == {
            'SSL_CLIENT_S_DN_CN': '',
        }, r.stdout
        data = env.tls_get_json(domain, "/index.json", options=[
            "--cert", clients_x.get_first("user1").cert_file
        ])
        assert data == {'domain': domain}
        r = env.tls_get(domain, "/vars.py?name=SSL_CLIENT_S_DN_CN", options=[
            "--cert", clients_x.get_first("user1").cert_file
        ])
        # with client cert, we expect the server variable to show? Do we?
        assert r.exit_code == 0, r.stderr
        assert r.json == {
            'SSL_CLIENT_S_DN_CN': 'Not Implemented',
        }, r.stdout

    def test_tls_12_auth_expired(self, env, cax_file, clients_x):
        conf = TlsTestConf(env=env, extras={
            env.domain_b: [
                "TLSClientCertificate required",
                f"TLSClientCA {cax_file}",
            ]
        })
        conf.add_md_vhosts(domains=[env.domain_b])
        conf.install()
        assert env.apache_restart() == 0
        # should not work
        r = env.tls_get(domain=env.domain_b, paths="/index.json", options=[
            "--cert", clients_x.get_first("user_expired").cert_file
        ])
        assert r.exit_code != 0

    def test_tls_12_auth_other_ca(self, env, cax_file, clients_y):
        conf = TlsTestConf(env=env, extras={
            env.domain_b: [
                "TLSClientCertificate required",
                f"TLSClientCA {cax_file}",
            ]
        })
        conf.add_md_vhosts(domains=[env.domain_b])
        conf.install()
        assert env.apache_restart() == 0
        # should not work
        r = env.tls_get(domain=env.domain_b, paths="/index.json", options=[
            "--cert", clients_y.get_first("user1").cert_file
        ])
        assert r.exit_code != 0
        # This will work, as the CA root is present in the CA file
        r = env.tls_get(domain=env.domain_b, paths="/index.json", options=[
            "--cert", env.ca.get_first("user1").cert_file
        ])
        assert r.exit_code == 0
