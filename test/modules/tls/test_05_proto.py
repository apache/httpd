import time
from datetime import timedelta
import socket
from threading import Thread

import pytest

from .conf import TlsTestConf
from .env import TlsTestEnv


class TestProto:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = TlsTestConf(env=env, extras={
            env.domain_a: "TLSProtocol TLSv1.3+",
            env.domain_b: [
                "# the commonly used name",
                "TLSProtocol TLSv1.2+",
                "# the numeric one (yes, this is 1.2)",
                "TLSProtocol TLSv0x0303+",
            ],
        })
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _function_scope(self, env):
        pass

    def test_tls_05_proto_1_2(self, env):
        r = env.tls_get(env.domain_b, "/index.json", options=["--tlsv1.2"])
        assert r.exit_code == 0, r.stderr
        if TlsTestEnv.curl_supports_tls_1_3():
            r = env.tls_get(env.domain_b, "/index.json", options=["--tlsv1.3"])
            assert r.exit_code == 0, r.stderr

    def test_tls_05_proto_1_3(self, env):
        r = env.tls_get(env.domain_a, "/index.json", options=["--tlsv1.3"])
        if TlsTestEnv.curl_supports_tls_1_3():
            assert r.exit_code == 0, r.stderr
        else:
            assert r.exit_code == 4, r.stderr

    def test_tls_05_proto_close(self, env):
        s = socket.create_connection(('localhost', env.https_port))
        time.sleep(0.1)
        s.close()

    def test_tls_05_proto_ssl_close(self, env):
        conf = TlsTestConf(env=env, extras={
            'base': "LogLevel ssl:debug",
            env.domain_a: "SSLProtocol TLSv1.3",
            env.domain_b: "SSLProtocol TLSv1.2",
        })
        for d in [env.domain_a, env.domain_b]:
            conf.add_vhost(domains=[d], port=env.https_port)
        conf.install()
        assert env.apache_restart() == 0
        s = socket.create_connection(('localhost', env.https_port))
        time.sleep(0.1)
        s.close()


