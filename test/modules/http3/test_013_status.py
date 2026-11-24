import json

import pytest

from .env import H3Conf

COUNTERS = {"live_workers", "total_connections", "total_streams",
            "total_bytes_read", "total_bytes_written"}


class TestStatus:

    def test_h3_013_01_counters(self, env):
        # only the child holding the UDP port has counters to report
        if env.mpm_module not in ("mpm_event", "mpm_worker"):
            pytest.skip(f"cannot limit {env.mpm_module} to one child")
        H3Conf(env).add_h3_vhost(directives=[
            "<Location /h3-status>",
            "  SetHandler http3-status",
            "</Location>",
        ]).add([
            "StartServers 1",
            "ServerLimit 1",
            "ThreadsPerChild 25",
            "MaxRequestWorkers 25",
            "MinSpareThreads 1",
            "MaxSpareThreads 25",
        ]).install()
        assert env.apache_restart() == 0
        assert env.wait_udp_port(env.https_port)
        r = env.curl_get(f"https://{env.h3_domain}:{env.https_port}/h3-status")
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200
        assert r.response["header"]["content-type"] == "application/json"
        status = json.loads(r.response["body"])
        assert set(status.keys()) == COUNTERS
        assert all(isinstance(v, int) and v >= 0 for v in status.values())
