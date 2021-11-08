import socket
import time

import pytest

from .env import H2Conf
from pyhttpd.curl import CurlPiper


class TestTimeout:

    # Check that base servers 'Timeout' setting is observed on SSL handshake
    def test_h2_105_01(self, env):
        conf = H2Conf(env)
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
    def test_h2_105_02(self, env):
        conf = H2Conf(env)
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
    def test_h2_105_03(self, env):
        conf = H2Conf(env)
        conf.add("""
            Timeout 10
            RequestReadTimeout handshake=1 header=5 body=10
            """)
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/necho.py")
        r = env.curl_get(url, 5, options=[
            "-vvv",
            "-F", ("count=%d" % 100),
            "-F", ("text=%s" % "abcdefghijklmnopqrstuvwxyz"),
            "-F", ("wait1=%f" % 1.5),
        ])
        assert r.response["status"] == 200

    def test_h2_105_10(self, env):
        # just a check without delays if all is fine
        conf = H2Conf(env)
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2test/delay")
        piper = CurlPiper(env=env, url=url)
        piper.start()
        stdout, stderr = piper.close()
        assert piper.exitcode == 0
        assert len("".join(stdout)) == 3 * 8192

    def test_h2_105_11(self, env):
        # short connection timeout, longer stream delay
        # receiving the first response chunk, then timeout
        conf = H2Conf(env)
        conf.add_vhost_cgi()
        conf.add("Timeout 1")
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2test/delay?5")
        piper = CurlPiper(env=env, url=url)
        piper.start()
        stdout, stderr = piper.close()
        assert len("".join(stdout)) == 8192

    def test_h2_105_12(self, env):
        # long connection timeout, short stream timeout
        # sending a slow POST
        conf = H2Conf(env)
        conf.add_vhost_cgi()
        conf.add("Timeout 10")
        conf.add("H2StreamTimeout 1")
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2test/delay?5")
        piper = CurlPiper(env=env, url=url)
        piper.start()
        for _ in range(3):
            time.sleep(2)
            try:
                piper.send("0123456789\n")
            except BrokenPipeError:
                break
        piper.close()
        assert piper.response
        assert piper.response['status'] == 408
