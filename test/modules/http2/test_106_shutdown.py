#
# mod-h2 test suite
# check HTTP/2 timeout behaviour
#
import time
from threading import Thread

import pytest

from .env import H2Conf
from pyhttpd.result import ExecResult


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
