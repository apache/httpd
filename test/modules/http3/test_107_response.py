import os
import time

import pytest

from .env import H3Conf, data_bytes, known_bug


class TestLogging:

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost(directives=[
            'LogFormat "%a|%H|%r|%>s|%B|%I|%O" h3',
            "CustomLog logs/h3_access h3",
        ]).install()
        assert env.apache_restart() == 0

    def log_lines(self, env, n, timeout=5):
        path = os.path.join(env.server_logs_dir, "h3_access")
        end = time.monotonic() + timeout
        while True:
            lines = open(path).read().splitlines() if os.path.isfile(path) else []
            if len(lines) >= n or time.monotonic() > end:
                return lines
            time.sleep(0.1)

    def test_h3_107_01_access_log(self, env):
        r = env.h3_client().get("/h3data-1k")
        assert r.status == 200, f"{r}"
        line = self.log_lines(env, 1)[-1]
        addr, proto, request, status, size, rx, tx = line.split("|")
        assert addr == "127.0.0.1"
        assert proto == "HTTP/3.0"
        assert request == "GET /h3data-1k HTTP/3.0"
        assert status == "200"
        assert size == "1024"
        known_bug(rx == "0" or tx == "0", "mod_logio counts no bytes for "
                  "HTTP/3 requests")
        assert int(rx) > 0 and int(tx) >= 1024, line


class TestResponseLimit:

    LIMIT = 50000

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost(directives=[
            f"H3MaxResponseBodySize {cls.LIMIT}",
        ]).install()
        assert env.apache_restart() == 0

    def test_h3_107_10_under_limit(self, env):
        r = env.h3_client().get("/h3data-1k")
        assert r.status == 200, f"{r}"
        assert r.body == data_bytes(1024)

    def test_h3_107_11_over_limit(self, env):
        r = env.h3_client().get("/h3data-100k")
        env.httpd_error_log.ignore_recent(
            matches=[r'.*exceeds H3MaxResponseBodySize'])
        assert r.status == 500, f"{r}"
        assert r.body == b"Response exceeded H3MaxResponseBodySize\n"


class TestStreaming:

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost().install()
        assert env.apache_restart() == 0

    def test_h3_107_20_flush(self, env):
        # stream.py flushes "first", sleeps 2 seconds, then writes "second"
        tcp = env.curl_get(f"https://{env.h3_domain}:{env.https_port}/cgi/stream.py",
                           options=["--http1.1", "-o", os.devnull, "-w",
                                    "%{time_starttransfer} %{time_total}"])
        ttfb, total = map(float, tcp.stdout.split())
        assert total - ttfb >= 1.5, f"no streaming over HTTP/1.1 either: {tcp.stdout}"
        r = env.h3_client().get("/cgi/stream.py")
        assert r.status == 200, f"{r}"
        assert r.body == b"first\nsecond\n"
        assert len(r.data_times) >= 2, f"body came in one piece: {r}"
        assert r.data_times[-1] - r.data_times[0] >= 1.5
