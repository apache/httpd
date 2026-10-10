import socket
import time
from threading import Thread

import pytest

from pyhttpd.depends import needs_dependency

from pyhttpd.conf import HttpdConf
from .env import SSLTestEnv


class SilentRedis:
    # accepts connections and never answers, so a client waits for its
    # read timeout

    def __init__(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.bind(('127.0.0.1', 0))
        self._socket.listen(5)
        self._socket.settimeout(0.2)
        self._done = False
        self._conns = []
        self._thread = Thread(target=self._run, daemon=True)

    @property
    def port(self):
        return self._socket.getsockname()[1]

    def _run(self):
        while not self._done:
            try:
                self._conns.append(self._socket.accept()[0])
            except socket.timeout:
                pass

    def start(self):
        self._thread.start()

    def stop(self):
        self._done = True
        self._thread.join(timeout=5)
        for c in self._conns:
            c.close()
        self._socket.close()


@needs_dependency("mod_socache_redis", SSLTestEnv.has_shared_module("socache_redis"),
                  reason="mod_socache_redis not available")
class TestSocacheRedis:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        # storing the session of a TLSv1.2 handshake waits for the redis reply
        env.httpd_error_log.add_ignored_lognos(["AH03478"])
        yield
        env.httpd_error_log.remove_ignored_lognos(["AH03478"])

    # RedisTimeout is passed to the redis client in whole seconds, a
    # positive value is rounded up, 0 does not wait at all
    @pytest.mark.parametrize(["timeout", "seconds"], [
        ["0", 0],
        ["1ms", 1],
        ["1s", 1],
        ["1500ms", 2],
    ])
    def test_ssl_004_01(self, env, timeout, seconds):
        redis = SilentRedis()
        redis.start()
        try:
            conf = HttpdConf(env, extras={
                "base": [
                    f"SSLSessionCache redis:127.0.0.1:{redis.port}",
                    f"RedisTimeout {timeout}",
                    "SSLProtocol TLSv1.2",
                ]
            })
            conf.add_vhost_test1()
            conf.install()
            assert env.apache_restart() == 0
            url = env.mkurl("https", "test1", "/")
            start = time.monotonic()
            r = env.curl_get(url, options=["--tlsv1.2", "--tls-max", "1.2",
                                           "--max-time", "10"])
            elapsed = time.monotonic() - start
        finally:
            redis.stop()
        assert r.exit_code == 0, f"{r.stdout}{r.stderr}"
        assert r.response["status"] == 200
        assert elapsed >= seconds - 0.2, f"waited only {elapsed:.1f}s"
        assert elapsed < seconds + 1.5, f"waited {elapsed:.1f}s"
