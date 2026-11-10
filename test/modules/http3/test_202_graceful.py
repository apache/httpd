import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from .env import H3Conf


class TestGracefulShutdown:
    """Test HTTP/3 GOAWAY sending and connection wind-down on graceful restart."""

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost().install()
        assert env.apache_restart() == 0

    def test_h3_202_01_goaway_sent_on_graceful_restart(self, env):
        env.require_curl_http3()
        url = env.mkurl("https", "test1", "/001.html")

        def do_get(_i):
            return env.curl_get(url, options=["--http3"])

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(do_get, i) for i in range(10)]
            assert env.apache_reload() == 0
            results = [f.result() for f in futures]

        succeeded = [r for r in results if r.exit_code == 0 and r.response is not None]
        for r in succeeded:
            assert r.response["status"] == 200

        log = logging.getLogger(__name__)
        pattern = re.compile(r".*\[http3:info].*sent HTTP/3 GOAWAY.*")
        try:
            env.httpd_error_log.scan_recent(pattern, timeout=10)
        except TimeoutError:
            log.warning("GOAWAY not seen after 10s, retrying with 10 more")
            env.httpd_error_log.scan_recent(pattern, timeout=10)

        assert env.is_live()
        time.sleep(1.5)
        r = env.curl_get(url, options=["--http3"])
        assert r.exit_code == 0, r.stderr + r.stdout
        assert r.response["status"] == 200
