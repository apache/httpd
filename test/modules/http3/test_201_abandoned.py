import re
import subprocess
import time

import pytest

from .env import H3Conf


class TestAbandonedConnectionCleanup:
    """Test that connection is cleaned up if client process is terminated."""

    def test_h3_201_01_abandoned_connection_is_reaped(self, env):
        env.require_curl_http3()
        H3Conf(env).add_h3_vhost().install()
        assert env.apache_restart() == 0

        url = env.mkurl("https", "test1", "/001.html")
        args = [env.curl, "-s", "--http3", "--max-time", "60"]
        args.extend(env.curl_resolve_args(url))
        args.append(url)

        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(0.3)
        finally:
            proc.kill()
            proc.wait(timeout=5)

        pattern = re.compile(r".*\[http3:info].*connection servicing done.*")
        env.httpd_error_log.scan_recent(pattern, timeout=15)

        assert env.is_live()
        r = env.curl_get(url, options=["--http3"])
        assert r.exit_code == 0, r.stderr + r.stdout
        assert r.response["status"] == 200
