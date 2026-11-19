import os
import subprocess

import pytest

from .env import H3Conf


def children_rss_kb(env) -> int:
    with open(os.path.join(env.server_logs_dir, "httpd.pid")) as fd:
        ppid = fd.read().strip()
    p = subprocess.run(["ps", "-A", "-o", "ppid=,rss="], capture_output=True,
                       text=True, check=True)
    rows = (line.split() for line in p.stdout.splitlines())
    return sum(int(rss) for parent, rss in rows if parent == ppid)


class TestStreamReclaim:
    """What a closed stream holds is given back while the connection lives
    on; the client gets the stream credit back either way."""

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost().install()
        assert env.apache_restart() == 0

    def test_h3_112_01_uni_streams(self, env):
        (before, after), r = env.h3_client(timeout=60).uni_streams(
            [500, 3000], lambda: children_rss_kb(env))
        assert r.status == 200, f"{r}"
        assert after - before < 8 * 1024, \
            f"httpd children grew from {before} to {after} KB over 3000 uni streams"

    def test_h3_112_02_cancelled_requests(self, env):
        # never dispatched, so no worker ever owned them
        cancelled = dict(path="/h3data-1k", reset=0x10c)
        before, after = env.h3_client(timeout=60).requests_probed(
            [[cancelled] * 200, [cancelled] * 2000], lambda: children_rss_kb(env))
        assert after - before < 8 * 1024, \
            f"httpd children grew from {before} to {after} KB over 2000 cancelled requests"
