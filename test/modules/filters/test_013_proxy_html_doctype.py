import os

import pytest

from pyhttpd.backport import not_backported
from pyhttpd.conf import HttpdConf

# "ProxyHTMLDocType HTML|XHTML [Legacy]" cleans up the document, dropping
# elements and attributes which HTML 4 does not have.  It relies on tables
# which libxml2 2.14 removed, so a module built with a newer libxml2
# refuses those forms rather than accept them and clean up nothing.
DOC = ('<html><head><title>t</title></head><body>'
       '<p class="ok" data-bogus="x">text<br>more</p>'
       '<font color="red">old</font>'
       '</body></html>')

ENFORCING = ["HTML", "XHTML", "HTML Legacy", "XHTML Legacy"]


class TestProxyHTMLDocType:

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        env.require(env.has_shared_module("proxy_html"),
                    "mod_proxy_html not available", dep="mod_proxy_html",
                    detected=f"no mod_proxy_html.so in {env.libexec_dir}")
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1", "phtml")
        os.makedirs(doc_dir, exist_ok=True)
        with open(os.path.join(doc_dir, "doctype.html"), "w") as f:
            f.write(DOC)

    def get(self, env, doctype):
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
            <Location "/phtml">
                SetEnv PROXY_HTML_FORCE 1
                ProxyHTMLEnable On
                ProxyHTMLLinks a href
                ProxyHTMLDocType {doctype}
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0
        r = env.curl_get(env.mkurl("http", "test1", "/phtml/doctype.html"))
        assert r.response["status"] == 200
        return r.response["body"].decode()

    # Either the form is refused, or it does what is documented.  (An
    # unpatched server fails this only if built with libxml2 >= 2.14.)
    @not_backported("gh-1104", "ProxyHTMLDocType with libxml2 2.14")
    @pytest.mark.parametrize("doctype", ENFORCING)
    def test_filters_013_01_enforcing(self, env, doctype):
        r = env.configtest([f"ProxyHTMLDocType {doctype}"])
        if r.exit_code != 0:
            assert "libxml2" in r.stderr
            return
        body = self.get(env, doctype)
        assert 'class="ok"' in body
        assert "data-bogus" not in body
        if "Legacy" not in doctype:
            assert "<font" not in body and "</font>" not in body
            assert "old" in body

    # The other forms never cleaned anything up.
    @pytest.mark.parametrize("doctype, declared", [
        ("HTML5", "<!DOCTYPE html>"),
        ("auto", None),
        ('"-//W3C//DTD HTML 4.01//EN"', "-//W3C//DTD HTML 4.01//EN"),
    ])
    def test_filters_013_02_other_forms(self, env, doctype, declared):
        body = self.get(env, doctype)
        if declared:
            assert body.startswith(declared)
        assert 'data-bogus="x"' in body
        assert '<font color="red">old</font>' in body
        # an empty element gets no end tag
        assert "text<br>more" in body
