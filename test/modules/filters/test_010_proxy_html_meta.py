import os

import pytest

from pyhttpd.conf import HttpdConf

from .env import FiltersTestEnv

# ProxyHTMLMeta lifts <meta http-equiv> tags into response headers.  The
# scan for the header name and the content value must stop at the end of
# the data read from the backend, which is not NUL terminated, so a tag
# right at the end of the body must not be read past.
#
# The documents are 4096 bytes, ending in the tag.  "EnableMMAP Off" makes
# httpd read the file into an allocated buffer rather than mmap it, so an
# over-read runs off the end of that buffer: on an unfixed server under
# ASan (the CI "ASan, pytest" job) it aborts the child and the request
# fails, which is the RED half of these cases.  Without ASan or a guard
# page the over-read may still go unnoticed.
DOC_SIZE = 4096
HEAD = "<html><head><title>t</title>"

WELL_FORMED = (HEAD + '<meta http-equiv="X-Meta-Test" content="lifted">'
               + "</head><body>ok</body></html>")
END_TAGS = {
    # Header-name scan runs off the end: no name.
    "no_name": "<meta http-equiv>",
    # Unterminated content quote: value scan runs off the end.
    "open_content": "<meta content='0;url=/x http-equiv=Refresh>",
    # Name scan ends empty while a content value is present.  Even once the
    # over-read is bounded, an empty header name must not be lifted, or
    # apr_table_setn(headers_out, "", ...) makes check_header turn the
    # request into a 500.
    "empty_name": "<meta content=x http-equiv>",
}


def pad_to(text, size):
    return HEAD + " " * (size - len(HEAD) - len(text)) + text


@pytest.mark.skipif(not FiltersTestEnv.has_shared_module("proxy_html"),
                    reason="mod_proxy_html not available")
class TestProxyHtmlMeta:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1", "phtml")
        os.makedirs(doc_dir, exist_ok=True)
        with open(os.path.join(doc_dir, "well_formed.html"), "w") as f:
            f.write(WELL_FORMED)
        for name, tag in END_TAGS.items():
            text = pad_to(tag, DOC_SIZE)
            assert len(text) == DOC_SIZE
            with open(os.path.join(doc_dir, f"{name}.html"), "w") as f:
                f.write(text)
        # "No i18n support found" when mod_xml2enc is not loaded.
        env.httpd_error_log.add_ignored_lognos(["AH01422"])
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": """
            <Location "/phtml/">
                SetEnv PROXY_HTML_FORCE 1
                ProxyHTMLEnable On
                ProxyHTMLMeta On
                ProxyHTMLLinks a href
                EnableMMAP Off
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def get(self, env, name):
        return env.curl_get(env.mkurl("http", "test1", f"/phtml/{name}.html"))

    # A well-formed tag is still lifted into a response header.
    def test_filters_010_01(self, env):
        r = self.get(env, "well_formed")
        assert r.response, "no response"
        assert r.response["status"] == 200
        assert r.response["header"].get("x-meta-test") == "lifted"

    # A tag at the very end of the body is served without a crash or a 500
    # and, having no usable header name, lifts no header.
    @pytest.mark.parametrize("name", list(END_TAGS))
    def test_filters_010_02(self, env, name):
        r = self.get(env, name)
        assert r.response, f"{name}: no response"
        assert r.response["status"] == 200, \
            f"{name}: status {r.response['status']}"
        assert "refresh" not in r.response["header"]
