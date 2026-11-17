import gzip
import os
import sys

import pytest

from pyhttpd.conf import HttpdConf

class TestModDeflateFilters:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")

        gz_dir = os.path.join(doc_dir, "filtertest")
        os.makedirs(gz_dir, exist_ok=True)
        gz_path = os.path.join(gz_dir, "hello.txt.gz")
        with gzip.open(gz_path, "wb") as f:
            f.write(b"Good morning, fellow!")

    def test_filters_009_01(self, env):
        """Without Accept-Encoding: gzip the INFLATE filter decompresses
        the .gz file so the client receives plain text."""
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": """
            <Location "/filtertest/">
                AddEncoding x-gzip .gz
                FilterDeclare uncompress
                FilterProvider uncompress INFLATE "%{req:Accept-Encoding} !~ /gzip/"
                FilterChain uncompress
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("http", "test1", "/filtertest/hello.txt.gz")
        r = env.curl_get(url)
        assert r.response, "no response"
        assert r.response["status"] == 200
        # The filter should have decompressed the content.
        ce = r.response["header"].get("content-encoding")
        assert ce is None or "gzip" not in ce, \
            f"expected no gzip Content-Encoding, got: {ce}"
        body = r.response["body"].decode()
        assert "Good morning, fellow!" in body, \
            f"expected decompressed body, got: {body!r}"

    def test_filters_009_02(self, env):
        """With Accept-Encoding: gzip the INFLATE filter is bypassed and the
        file is served compressed; curl --compressed decompresses it."""
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": """
            <Location "/filtertest/">
                AddEncoding x-gzip .gz
                FilterDeclare uncompress
                FilterProvider uncompress INFLATE "%{req:Accept-Encoding} !~ /gzip/"
                FilterChain uncompress
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("http", "test1", "/filtertest/hello.txt.gz")
        r = env.curl_get(url, options=[
            "-H", "Accept-Encoding: gzip",
            "--compressed",
        ])
        assert r.response, "no response"
        assert r.response["status"] == 200
        body = r.response["body"].decode()
        assert "Good morning, fellow!" in body, \
            f"expected original content (decompressed by curl), got: {body!r}"
