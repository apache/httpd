import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from .env import H3Conf

QUIC_CONNECTION_REFUSED = 0x2


class TestConnectionLimit:

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost(directives=[
            "H3MaxConnections 1",
        ]).install()
        assert env.apache_restart() == 0

    def test_h3_113_01_over_limit_fails_fast(self, env):
        def second_client():
            start = time.monotonic()
            try:
                r = env.h3_client(timeout=15).get("/001.html")
            except Exception as e:
                r = e
            return r, time.monotonic() - start

        def probe():
            # its own event loop, while the first connection stays open
            with ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(second_client).result()

        (second, elapsed), = env.h3_client(timeout=60).requests_probed(
            [[dict(path="/001.html")]], probe)
        env.httpd_error_log.ignore_recent(
            matches=[r'.*dropping QUIC connection: at H3MaxConnections limit.*'])
        assert second.terminated is not None, f"{second!r}"
        assert second.terminated.error_code == QUIC_CONNECTION_REFUSED, f"{second!r}"
        assert elapsed < 5, f"refused connection took {elapsed:.1f}s to fail"
