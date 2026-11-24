import textwrap

import pytest

from pyhttpd.conf import HttpdConf


class TestAutoindex:

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        domain = f"autoindex.{env.http_tld}"
        conf = HttpdConf(env, extras={
            'base': textwrap.dedent(f"""
            LogLevel autoindex:trace1
            <Directory "{env.server_docs_dir}/autoindex/listing">
                Options +Indexes
                IndexOptions FancyIndexing ScanHTMLTitles
            </Directory>
            <Directory "{env.server_docs_dir}/autoindex/listing">
                <If "%{{QUERY_STRING}} == 'xhtml'">
                    IndexOptions XHTML Charset=ISO-8859-2
                </If>
                <ElseIf "%{{QUERY_STRING}} == 'nocharset'">
                    IndexOptions Charset=
                </ElseIf>
                <Else>
                    IndexOptions Charset=ISO-8859-2
                </Else>
            </Directory>
            """),
        })
        conf.add_vhost(domains=[domain], port=env.http_port,
                       doc_root="htdocs/autoindex")
        conf.install()
        assert env.apache_restart() == 0

    def test_generators_002_01_scan_title_bare_amp(self, env):
        """A ScanHTMLTitles description ending in a bare '&' (no ';'), as in
        an "AT&T" <title>, must be rendered without reading past the end of
        the description.  Before the fix this walked one byte past the
        terminating NUL, which ASAN flags as a heap over-read."""
        r = env.curl_get(env.mkurl("http", "autoindex", "/listing/"))
        assert r.response["status"] == 200
        assert "AT&T" in r.response["body"].decode()

    def test_generators_002_02_charset_meta_html(self, env):
        """IndexOptions Charset= adds a <meta> to the HTML 4.01 document,
        before <title>, without XHTML-style self-closing."""
        r = env.curl_get(env.mkurl("http", "autoindex", "/listing/"))
        assert r.response["status"] == 200
        body = r.response["body"].decode()
        meta = '<meta http-equiv="Content-Type" content="text/html; ' \
               'charset=ISO-8859-2">'
        assert meta in body, body
        assert body.index(meta) < body.index("<title>"), body

    def test_generators_002_03_charset_meta_xhtml(self, env):
        r = env.curl_get(env.mkurl("http", "autoindex", "/listing/?xhtml"))
        assert r.response["status"] == 200
        body = r.response["body"].decode()
        meta = '<meta http-equiv="Content-Type" content="text/html; ' \
               'charset=ISO-8859-2" />'
        assert meta in body, body
        assert body.index(meta) < body.index("<title>"), body

    def test_generators_002_04_empty_charset_no_meta(self, env):
        r = env.curl_get(env.mkurl("http", "autoindex",
                                   "/listing/?nocharset"))
        assert r.response["status"] == 200
        assert "http-equiv" not in r.response["body"].decode()
