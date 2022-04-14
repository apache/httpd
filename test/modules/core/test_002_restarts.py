import os

import pytest

from .env import CoreTestEnv
from pyhttpd.conf import HttpdConf


@pytest.mark.skipif(condition='STRESS_TEST' not in os.environ,
                    reason="STRESS_TEST not set in env")
@pytest.mark.skipif(condition=not CoreTestEnv().h2load_is_at_least('1.41.0'),
                    reason="h2load unavailable or misses --connect-to option")
class TestRestarts:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env, extras={
            'base': f"""
StartServers 1
ServerLimit 4
ThreadLimit 2
ThreadsPerChild 2
MinSpareThreads 2
MaxSpareThreads 4
MaxRequestWorkers 8
MaxConnectionsPerChild 0
        """,
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0

    def test_core_002_01(self, env):
        clients = 6
        total_requests = clients * 10
        conn_per_client = 5
        url = env.mkurl("https", "cgi", "/delay.py")
        args = [env.h2load, f"--connect-to=localhost:{env.https_port}",
                "--h1",                                 # use only http/1.1
                "-n", str(total_requests),              # total # of requests to make
                "-c", str(conn_per_client * clients),   # total # of connections to make
                "-r", str(clients),                     # connections at a time
                "--rate-period", "2",                   # create conns every 2 sec
                url,
                ]
        r = env.run(args)
        assert 0 == r.exit_code
        r = env.h2load_status(r)
        assert r.results["h2load"]["requests"] == {
            "total": total_requests, "started": total_requests,
            "done": total_requests, "succeeded": total_requests
        }, f"{r.stdout}"

