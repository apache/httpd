import re

import pytest

from pyhttpd.conf import HttpdConf


class TestForwardProxy:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env)
        conf.start_vhost(domains=[env.d_forward], port=env.http_port)
        conf.add([
            "ProxyRequests On",
            "ProxyVia On",
            "LogLevel proxy:trace5",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

    def _proxy_connect(self, env, hostname):
        start_pos = env.httpd_error_log.current_pos()
        env.curl_raw(f"https://{hostname}:8443", options=[
            '-x', f'http://localhost:{env.http_port}',
            '-k',
            '--connect-timeout', '5',
            '--max-time', '10',
        ])
        return start_pos

    def _check_no_ah10262(self, env, start_pos):
        found = env.httpd_error_log.wait_for(
            re.compile(r'.*AH10262.*'), start_pos, timeout=2)
        env.httpd_error_log.ignore_recent(
            lognos=["AH00898", "AH00961", "AH02327"],
            matches=[r'.*proxy:error.*', r'.*proxy_connect:error.*'])
        return found

    # Long DNS name (>14 chars) must not trigger AH10262 "overlong proxy
    # URL scheme".
    def test_proxy_007_01(self, env):
        long_host = "www.thisisaverylonghostaddressblablablabla123.com"
        start_pos = self._proxy_connect(env, long_host)
        found = self._check_no_ah10262(env, start_pos)
        assert not found, "Long hostname should not trigger AH10262"

    # Short DNS name — control test.
    def test_proxy_007_02(self, env):
        short_host = "www.vshn.com"
        start_pos = self._proxy_connect(env, short_host)
        found = self._check_no_ah10262(env, start_pos)
        assert not found, "Short hostname should not trigger AH10262"
