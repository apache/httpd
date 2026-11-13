"""mod_proxy_hcheck's log messages never include the configured hcuri,
only the worker's base scheme://host:port -- so a health check configured
with e.g. "hcuri=/support" cannot be told apart from one with no hcuri at
all in the logs (PR 66042).
"""

import re

import pytest

from pyhttpd.conf import HttpdConf
from pyhttpd.depends import needs_dependency

from .env import ProxyTestEnv


@needs_dependency("mod_proxy_hcheck", ProxyTestEnv.has_shared_module("proxy_hcheck"),
                  reason="mod_proxy_hcheck not available")
class TestHcheckLogUri:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env)
        conf.add([
            '<Proxy "balancer://hcheckuri">',
            f'    BalancerMember "http://127.0.0.1:{env.proxy_port}" '
            'hcmethod=GET hcuri=/hcheck-uri-marker hcinterval=1 hcfails=1',
            '</Proxy>',
            'ProxyPass "/hcu/" "balancer://hcheckuri/"',
        ])
        conf.install()
        # capture the log position *before* the restart: the health check
        # watchdog starts almost immediately and only ever logs the
        # DISABLING transition once, so reading current_pos() after the
        # restart can race past it and leave wait_for() waiting for a line
        # that already went by.
        TestHcheckLogUri.start_pos = env.httpd_error_log.current_pos()
        assert env.apache_restart() == 0

    def test_proxy_09_01_hcuri_is_logged(self, env):
        assert env.httpd_error_log.wait_for(
            re.compile(r'.*Health check DISABLING .*uri=/hcheck-uri-marker.*'),
            self.start_pos, timeout=10), \
            "expected a 'Health check DISABLING' log line naming the " \
            "configured hcuri (/hcheck-uri-marker), not just the worker's " \
            "base URL"
        # the health check's own (expected, deliberately provoked) connect
        # failures against the unused backend port
        env.httpd_error_log.ignore_recent(lognos=["AH00957"])
