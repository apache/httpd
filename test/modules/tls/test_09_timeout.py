import socket
from datetime import timedelta

import pytest

from .conf import TlsTestConf


class TestTimeout:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = TlsTestConf(env=env, extras={
            'base': "RequestReadTimeout handshake=1",
        })
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _function_scope(self, env):
        pass

    def test_tls_09_timeout_handshake(self, env):
        # in domain_b root, the StdEnvVars is switch on
        s = socket.create_connection(('localhost', env.https_port))
        s.send(b'1234')
        s.settimeout(0.0)
        try:
            s.recv(1024)
            assert False, "able to recv() on a TLS connection before we sent a hello"
        except BlockingIOError:
            pass
        s.settimeout(3.0)
        try:
            while True:
                buf = s.recv(1024)
                if not buf:
                    break
                print("recv() -> {0}".format(buf))
        except (socket.timeout, BlockingIOError):
            assert False, "socket not closed as handshake timeout should trigger"
        s.close()
