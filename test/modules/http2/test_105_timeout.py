import socket
import pytest

from h2_conf import HttpdConf


class TestStore:

    # Check that base servers 'Timeout' setting is observed on SSL handshake
    def test_105_01(self, env):
        conf = HttpdConf(env)
        conf.add("""
            AcceptFilter http none
            Timeout 1.5
            """)
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        host = 'localhost'
        # read with a longer timeout than the server 
        sock = socket.create_connection((host, int(env.https_port)))
        try:
            # on some OS, the server does not see our connection until there is
            # something incoming
            sock.send(b'0')
            sock.settimeout(4)
            buff = sock.recv(1024)
            assert buff == b''
        except Exception as ex:
            print(f"server did not close in time: {ex}")
            assert False
        sock.close()
        # read with a shorter timeout than the server 
        sock = socket.create_connection((host, int(env.https_port)))
        try:
            sock.settimeout(0.5)
            sock.recv(1024)
            assert False
        except Exception as ex:
            print(f"as expected: {ex}")
        sock.close()

    # Check that mod_reqtimeout handshake setting takes effect
    def test_105_02(self, env):
        conf = HttpdConf(env)
        conf.add("""
            AcceptFilter http none
            Timeout 10
            RequestReadTimeout handshake=1 header=5 body=10
            """)
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        host = 'localhost'
        # read with a longer timeout than the server 
        sock = socket.create_connection((host, int(env.https_port)))
        try:
            # on some OS, the server does not see our connection until there is
            # something incoming
            sock.send(b'0')
            sock.settimeout(4)
            buff = sock.recv(1024)
            assert buff == b''
        except Exception as ex:
            print(f"server did not close in time: {ex}")
            assert False
        sock.close()
        # read with a shorter timeout than the server 
        sock = socket.create_connection((host, int(env.https_port)))
        try:
            sock.settimeout(0.5)
            sock.recv(1024)
            assert False
        except Exception as ex:
            print(f"as expected: {ex}")
        sock.close()

    # Check that mod_reqtimeout handshake setting do no longer apply to handshaked 
    # connections. See <https://github.com/icing/mod_h2/issues/196>.
    def test_105_03(self, env):
        conf = HttpdConf(env)
        conf.add("""
            Timeout 10
            RequestReadTimeout handshake=1 header=5 body=10
            """)
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/necho.py")
        r = env.curl_get(url, 5, [
            "-vvv",
            "-F", ("count=%d" % 100),
            "-F", ("text=%s" % "abcdefghijklmnopqrstuvwxyz"),
            "-F", ("wait1=%f" % 1.5),
        ])
        assert 200 == r.response["status"]
