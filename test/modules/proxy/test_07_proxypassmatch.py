import re

import pytest

from pyhttpd.conf import HttpdConf


class TestProxyPassMatch:

    @staticmethod
    def _install(env, extra=None):
        conf = HttpdConf(env)
        conf.add("LogLevel proxy:trace2")
        conf.start_vhost(domains=[env.d_reverse], port=env.https_port)
        conf.add([
            f"ProxyPassMatch ^/something/(\\d+)/others$ "
            f"http://127.0.0.1:{env.http_port}/something/$1/others timeout=500",
        ] + (extra or []))
        conf.end_vhost()
        conf.add_vhost(domains=[env.d_reverse], port=env.http_port, doc_root='htdocs/test1')
        conf.install()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        self._install(env)

    @staticmethod
    def _get(env, path):
        # returns the response and the error log position before the request
        pos = env.httpd_error_log.current_pos()
        r = env.curl_get(f"https://{env.d_reverse}:{env.https_port}{path}", 5)
        assert r.exit_code == 0, f"{r.stdout}{r.stderr}"
        return r, pos

    @staticmethod
    def _logged(env, pos, pattern):
        return env.httpd_error_log.wait_for(re.compile(pattern), pos, timeout=1)

    # the worker created by ProxyPassMatch is found, no matter how many
    # characters the backreference expands to
    @pytest.mark.parametrize("ident", ["1", "9", "10", "123"])
    def test_proxy_07_001(self, env, ident):
        r, pos = self._get(env, f"/something/{ident}/others")
        assert r.response["status"] == 404
        assert self._logged(
            env, pos,
            rf".*found worker http://127\.0\.0\.1:\d+/something/\$1/others "
            rf"for http://127\.0\.0\.1:\d+/something/{ident}/others\n")
        assert not self._logged(env, pos, r".*using default reverse proxy worker")

    # a request not matching the regex is not proxied via the match worker
    @pytest.mark.parametrize("path", ["/something/abc/others", "/something/1/other"])
    def test_proxy_07_002(self, env, path):
        r, pos = self._get(env, path)
        assert r.response["status"] == 404
        assert not self._logged(env, pos, r".*found worker .*/something/\$1/others")

    # a plain ProxyPass keeps selecting its own worker, even though the
    # URL is shorter than the name of the ProxyPassMatch worker, and
    # the longer ProxyPassMatch worker still wins where it matches
    def test_proxy_07_003(self, env):
        self._install(env, [f"ProxyPass /plain/ http://127.0.0.1:{env.http_port}/"])
        r, pos = self._get(env, "/plain/alive.json")
        assert r.response["status"] == 200
        assert self._logged(
            env, pos,
            r".*found worker http://127\.0\.0\.1:\d+/ "
            r"for http://127\.0\.0\.1:\d+/alive\.json\n")
        r, pos = self._get(env, "/something/1/others")
        assert r.response["status"] == 404
        assert self._logged(
            env, pos,
            r".*found worker http://127\.0\.0\.1:\d+/something/\$1/others "
            r"for http://127\.0\.0\.1:\d+/something/1/others\n")
