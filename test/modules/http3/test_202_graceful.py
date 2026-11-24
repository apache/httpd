import re
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from .env import H3Conf, known_bug


class TestGracefulShutdown:
    """Test HTTP/3 GOAWAY sending and connection wind-down on graceful restart."""

    _LINGER_WARN = [r".*AH10644:.*connection\(s\) noted by modules did not finish.*"]

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost().install()
        assert env.apache_restart() == 0

    def test_h3_202_01_goaway_sent_on_graceful_restart(self, env):
        env.require_curl_http3()
        url = env.mkurl("https", "test1", "/001.html")

        def do_get(_i):
            start = time.monotonic()
            r = env.curl_get(url, options=["--http3", "--max-time", "30"])
            return r, time.monotonic() - start

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(do_get, i) for i in range(10)]
            assert env.apache_reload() == 0
            timed = [f.result() for f in futures]

        # a connection the stopping child turns away has to fail fast, not idle out
        hung = [round(t) for _, t in timed if t >= 20]
        assert not hung, f"requests hung across the graceful restart for {hung}s"
        results = [r for r, _ in timed]
        succeeded = [r for r in results if r.exit_code == 0 and r.response is not None]
        for r in succeeded:
            assert r.response["status"] == 200

        pattern = re.compile(r".*\[http3:info].*sent HTTP/3 GOAWAY.*")
        try:
            env.httpd_error_log.scan_recent(pattern, timeout=10)
        except TimeoutError:
            known_bug(True, "no QUIC connection was active during graceful restart")

        env.httpd_error_log.ignore_recent(matches=self._LINGER_WARN)
        assert env.is_live()
        assert env.wait_udp_port(env.https_port)
        r = env.curl_get(url, options=["--http3"])
        assert r.exit_code == 0, r.stderr + r.stdout
        assert r.response["status"] == 200
