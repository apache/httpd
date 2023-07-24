#
# mod-h2 test suite
# check HTTP/2 timeout behaviour
#
import time
from threading import Thread

import pytest

from .env import H2Conf, H2TestEnv
from pyhttpd.result import ExecResult


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestShutdown:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = H2Conf(env)
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0

    def test_h2_106_01(self, env):
        url = env.mkurl("https", "cgi", "/necho.py")
        lines = 100000
        text = "123456789"
        wait2 = 1.0
        self.r = None
        def long_request():
            args = ["-vvv",
                    "-F", f"count={lines}",
                    "-F", f"text={text}",
                    "-F", f"wait2={wait2}",
                    ]
            self.r = env.curl_get(url, 5, options=args)

        t = Thread(target=long_request)
        t.start()
        time.sleep(0.5)
        assert env.apache_reload() == 0
        t.join()
        # noinspection PyTypeChecker
        time.sleep(1)
        r: ExecResult = self.r
        assert r.exit_code == 0
        assert r.response, f"no response via {r.args} in {r.stderr}\nstdout: {len(r.stdout)} bytes"
        assert r.response["status"] == 200, f"{r}"
        assert len(r.response["body"]) == (lines * (len(text)+1)), f"{r}"

    def test_h2_106_02(self, env):
        # PR65731: invalid GOAWAY frame at session start when
        # MaxRequestsPerChild is reached
        # Create a low limit and only 2 children, so we'll encounter this easily
        conf = H2Conf(env, extras={
            'base': [
                "ServerLimit 2",
                "MaxRequestsPerChild 3"
            ]
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "test1", "/index.html")
        for i in range(7):
            r = env.curl_get(url, options=['-v'])
            # requests should succeed, but rarely connections get closed
            # before the response is received
            if r.exit_code in [16, 55]:
                # curl send error
                assert r.response is None
            else:
                assert r.exit_code == 0, f"failed on {i}. request: {r.stdout} {r.stderr}"
                assert r.response["status"] == 200
                assert "HTTP/2" == r.response["protocol"]
        #
        env.httpd_error_log.ignore_recent(
            lognos = [
                "AH03490"   # scoreboard is full, not at MaxRequestWorkers
            ]
        )