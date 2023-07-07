from datetime import timedelta

import pytest

from .conf import TlsTestConf
from .env import TlsTestEnv


class TestSni:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = TlsTestConf(env=env)
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _function_scope(self, env):
        pass

    def test_tls_03_sni_get_a(self, env):
        # do we see the correct json for the domain_a?
        data = env.tls_get_json(env.domain_a, "/index.json")
        assert data == {'domain': env.domain_a}

    def test_tls_03_sni_get_b(self, env):
        # do we see the correct json for the domain_a?
        data = env.tls_get_json(env.domain_b, "/index.json")
        assert data == {'domain': env.domain_b}

    def test_tls_03_sni_unknown(self, env):
        # connection will be denied as cert does not cover this domain
        domain_unknown = "unknown.test"
        r = env.tls_get(domain_unknown, "/index.json")
        assert r.exit_code != 0
        #
        env.httpd_error_log.ignore_recent(
            lognos = [
                "AH10353"   # cannot decrypt peer's message
            ]
        )

    def test_tls_03_sni_request_other_same_config(self, env):
        # do we see the first vhost response for another domain with different certs?
        r = env.tls_get(env.domain_a, "/index.json", options=[
            "-vvvv", "--header", "Host: {0}".format(env.domain_b)
        ])
        # request is marked as misdirected
        assert r.exit_code == 0
        assert r.json is None
        assert r.response['status'] == 421
        #
        env.httpd_error_log.ignore_recent(
            lognos = [
                "AH10345"   # Connection host selected via SNI and request have incompatible TLS configurations
            ]
        )

    def test_tls_03_sni_request_other_other_honor(self, env):
        # do we see the first vhost response for an unknown domain?
        conf = TlsTestConf(env=env, extras={
            env.domain_a: "TLSProtocol TLSv1.2+",
            env.domain_b: "TLSProtocol TLSv1.3+"
        })
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 0
        r = env.tls_get(env.domain_a, "/index.json", options=[
            "-vvvv", "--tls-max", "1.2", "--header", "Host: {0}".format(env.domain_b)
        ])
        # request denied
        assert r.exit_code == 0
        assert r.json is None
        #
        env.httpd_error_log.ignore_recent(
            lognos = [
                "AH10345"   # Connection host selected via SNI and request have incompatible TLS configurations
            ]
        )

    @pytest.mark.skip('openssl behaviour changed on ventura, unreliable')
    def test_tls_03_sni_bad_hostname(self, env):
        # curl checks hostnames we give it, but the openssl client
        # does not. Good for us, since we need to test it.
        r = env.openssl(["s_client", "-connect",
                          "localhost:{0}".format(env.https_port),
                          "-servername", b'x\x2f.y'.decode()])
        assert r.exit_code == 1, r.stderr
