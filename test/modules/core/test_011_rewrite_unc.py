import re
import sys

import pytest

from pyhttpd.conf import HttpdConf

# UNCList only exists on Windows
pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="UNCList is a Windows feature")


class TestRewriteUnc:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": [
                "RewriteEngine On",
                'RewriteRule ^/v/(.*)$ "//$1"',
                'RewriteRule ^/vunc/(.*)$ "//$1" [UNC]',
            ],
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    # No UNCList, all UNC paths are refused. A UNC path made by a
    # RewriteRule must be refused as well, and before the host in it is
    # contacted, which takes a long time for one that does not answer.
    # The addresses are not routed (RFC 5737), a different one for
    # each request as failed lookups are cached.
    @pytest.mark.parametrize("path, host", [
        ["/v", "203.0.113.61"],
        ["/vunc", "203.0.113.62"],
    ])
    def test_core_011_01(self, env, path, host):
        pos = env.httpd_error_log.current_pos()
        url = env.mkurl("http", "test1", f"{path}/{host}/share/f.txt")
        r = env.curl_get(url, options=["--max-time", "5"])
        assert r.response, f"no timely response, UNC host contacted? {r.stderr}"
        assert r.response["status"] == 404
        assert env.httpd_error_log.wait_for(
            re.compile(r".*AH10504: check_unc: UNC path //" + host), pos), \
            "UNCList was not consulted"
        env.httpd_error_log.ignore_recent(lognos=["AH10504"])
