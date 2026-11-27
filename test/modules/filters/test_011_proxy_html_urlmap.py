import os

import pytest

from pyhttpd.backport import not_backported, skip_not_backported
from pyhttpd.conf import HttpdConf

# ProxyHTMLURLMap rules with a regex ('R') which is interpolated per
# request ('v'): the pattern is only compiled once the request's
# environment is known, and may then turn out not to be a regex at all.
DOC = '<html><body><a href="/Zed/x">link</a></body></html>'

# Logged when the pattern for a request does not compile.
NO_COMPILE = r'.*ProxyHTMLURLMap: could not compile regex.*'


class TestProxyHTMLURLMap:

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        env.require(env.has_shared_module("proxy_html"),
                    "mod_proxy_html not available", dep="mod_proxy_html",
                    detected=f"no mod_proxy_html.so in {env.libexec_dir}")
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1", "phtml")
        os.makedirs(doc_dir, exist_ok=True)
        with open(os.path.join(doc_dir, "doc.html"), "w") as f:
            f.write(DOC)
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": """
            SetEnvIf X-Foo "(.+)" FOO=$1
            <Location "/phtml">
                SetEnv PROXY_HTML_FORCE 1
                ProxyHTMLEnable On
                ProxyHTMLLinks a href
            </Location>
            <Location "/phtml/interp">
                ProxyHTMLInterp On
                ProxyHTMLURLMap "${FOO}" "X" Rv
            </Location>
            <Location "/phtml/icase">
                ProxyHTMLInterp On
                ProxyHTMLURLMap "${FOO}" "X" Rvi
            </Location>
            <Location "/phtml/nointerp">
                ProxyHTMLURLMap "Z.d" "X" Rv
            </Location>
            Alias /phtml/interp %s
            Alias /phtml/icase %s
            Alias /phtml/nointerp %s
            """ % ((doc_dir,) * 3),
        })
        conf.add_vhost_test1()
        conf.install()
        # The core warns that ${FOO} is not a variable it can expand.
        env.httpd_error_log.add_ignored_lognos(["AH00111"])
        assert env.apache_restart() == 0

    def get(self, env, path, foo=None):
        options = ["-H", f"X-Foo: {foo}"] if foo else None
        r = env.curl_get(env.mkurl("http", "test1", path), options=options)
        assert r.response["status"] == 200
        return r.response["body"].decode()

    def test_filters_011_01_interpolated_regex(self, env):
        assert 'href="/X/x"' in self.get(env, "/phtml/interp/doc.html", "Z.d")

    # The interpolated pattern is not a regex: the rule is ignored.
    @skip_not_backported("gh-1104", "invalid interpolated regex")
    def test_filters_011_02_interpolated_regex_invalid(self, env):
        assert 'href="/Zed/x"' in self.get(env, "/phtml/interp/doc.html", "[")
        env.httpd_error_log.ignore_recent(matches=[NO_COMPILE])
        # ... and the next request is not affected by it.
        assert 'href="/X/x"' in self.get(env, "/phtml/interp/doc.html", "Zed")

    # The regex flags apply to an interpolated pattern too.
    @not_backported("gh-1104", "regex flags with interpolation")
    def test_filters_011_03_interpolated_regex_flags(self, env):
        assert 'href="/X/x"' in self.get(env, "/phtml/icase/doc.html", "zED")
        assert 'href="/Zed/x"' in self.get(env, "/phtml/interp/doc.html", "zED")

    # Without ProxyHTMLInterp nothing is interpolated, and the pattern is
    # used as it was written.
    @skip_not_backported("gh-1104", "interpolated regex without ProxyHTMLInterp")
    def test_filters_011_04_regex_without_interp(self, env):
        assert 'href="/X/x"' in self.get(env, "/phtml/nointerp/doc.html")

    @not_backported("gh-1104", "invalid regex is a configuration error")
    def test_filters_011_05_invalid_regex_config(self, env):
        r = env.configtest(['ProxyHTMLURLMap "[" "X" R'])
        assert r.exit_code != 0
        assert "ProxyHTMLURLMap" in r.stderr

    def test_filters_011_06_valid_regex_config(self, env):
        r = env.configtest(['ProxyHTMLURLMap "[a-z]" "X" R'])
        assert r.exit_code == 0, r.stderr
