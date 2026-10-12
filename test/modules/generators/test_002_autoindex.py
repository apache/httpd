import textwrap

import pytest

from pyhttpd.conf import HttpdConf


class TestAutoindex:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        domain = f"autoindex.{env.http_tld}"
        conf = HttpdConf(env, extras={
            'base': textwrap.dedent(f"""
            LogLevel autoindex:trace1
            <Directory "{env.server_docs_dir}/autoindex/listing">
                Options +Indexes
                IndexOptions FancyIndexing ScanHTMLTitles
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
