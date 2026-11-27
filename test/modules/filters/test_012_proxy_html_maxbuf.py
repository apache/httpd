import os

import pytest

from pyhttpd.backport import not_backported
from pyhttpd.conf import HttpdConf

# ProxyHTMLMaxBufSize limits how much of an inline script, stylesheet or
# comment is buffered for rewriting with ProxyHTMLExtended: anything
# larger is passed through as it is, and logged.
MAXBUF = 4096
LINE = 'var u = "http://backend.example/x";\n'
SMALL = LINE * 10
LARGE = LINE * (3 * MAXBUF // len(LINE))
COMMENT = ' see http://backend.example/x ' * (3 * MAXBUF // 30)

DOCS = {
    "small.html": f'<html><head><script>{SMALL}</script></head>'
                  '<body><p>text</p></body></html>',
    # an element under the limit after one over it is still rewritten
    "large.html": f'<html><head><script>{LARGE}</script>'
                  f'<style>{SMALL}</style></head>'
                  '<body><p>text</p></body></html>',
    "comment.html": f'<html><body><p><!--{COMMENT}--></p>'
                    f'<script>{SMALL}</script></body></html>',
}

NO_DIRECTIVE = not_backported("gh-1104", "ProxyHTMLMaxBufSize")

TOO_LARGE = r'.*larger than ProxyHTMLMaxBufSize.*'


class TestProxyHTMLMaxBufSize:

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        env.require(env.has_shared_module("proxy_html"),
                    "mod_proxy_html not available", dep="mod_proxy_html",
                    detected=f"no mod_proxy_html.so in {env.libexec_dir}")
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1", "phtml")
        os.makedirs(doc_dir, exist_ok=True)
        for name, text in DOCS.items():
            with open(os.path.join(doc_dir, name), "w") as f:
                f.write(text)
        cls.doc_dir = doc_dir

    def configure(self, env, maxbuf):
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
            <Location "/phtml">
                SetEnv PROXY_HTML_FORCE 1
                ProxyHTMLEnable On
                ProxyHTMLExtended On
                ProxyHTMLLinks a href
                ProxyHTMLURLMap http://backend.example/ /proxy/
                {maxbuf}
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def get(self, env, name):
        r = env.curl_get(env.mkurl("http", "test1", f"/phtml/{name}"))
        assert r.response["status"] == 200
        return r.response["body"].decode()

    @NO_DIRECTIVE
    def test_filters_012_01_limit(self, env):
        self.configure(env, f"ProxyHTMLMaxBufSize {MAXBUF}")
        body = self.get(env, "small.html")
        assert SMALL.replace("http://backend.example/", "/proxy/") in body
        assert "backend.example" not in body

        # Over the limit: all of the script comes through untouched, the
        # stylesheet after it is rewritten.
        body = self.get(env, "large.html")
        assert f"<script>{LARGE}</script>" in body
        assert ("<style>" + SMALL.replace("http://backend.example/", "/proxy/")
                + "</style>") in body
        env.httpd_error_log.ignore_recent(matches=[TOO_LARGE])

        body = self.get(env, "comment.html")
        assert f"<!--{COMMENT}-->" in body
        assert ("<script>" + SMALL.replace("http://backend.example/", "/proxy/")
                + "</script>") in body
        env.httpd_error_log.ignore_recent(matches=[TOO_LARGE])

    @pytest.mark.parametrize("maxbuf", [
        pytest.param("ProxyHTMLMaxBufSize 0", marks=NO_DIRECTIVE),
        pytest.param("ProxyHTMLMaxBufSize 1M", marks=NO_DIRECTIVE),
        "",
    ])
    def test_filters_012_02_under_limit(self, env, maxbuf):
        self.configure(env, maxbuf)
        for name in ["large.html", "comment.html"]:
            assert "backend.example" not in self.get(env, name)

    @pytest.mark.parametrize("value, ok", [
        pytest.param("64K", True, marks=NO_DIRECTIVE),
        pytest.param("0", True, marks=NO_DIRECTIVE),
        ("-1", False), ("lots", False),
    ])
    def test_filters_012_03_config(self, env, value, ok):
        r = env.configtest([f"ProxyHTMLMaxBufSize {value}"])
        assert (r.exit_code == 0) == ok, r.stderr
