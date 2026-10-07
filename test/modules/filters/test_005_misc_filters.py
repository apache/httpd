import gzip
import os
import sys

import pytest

from pyhttpd.conf import HttpdConf

# Miscellaneous filter tests ported from noe-tests FiltersHttpdTest.groovy:
# mod_ext_filter, mod_include (SSI), and mod_deflate with FilterChain.


class TestMiscFilters:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")

        # --- ext_filter test data ---
        ext_dir = os.path.join(doc_dir, "extfiltertest")
        os.makedirs(ext_dir, exist_ok=True)
        with open(os.path.join(ext_dir, "hello.txt.crap"), "w") as f:
            f.write("crap not allowed during worktime\n"
                    "recycling can save the earth\n")

        # --- SSI test data ---
        ssi_dir = os.path.join(doc_dir, "includestest")
        os.makedirs(ssi_dir, exist_ok=True)
        with open(os.path.join(ssi_dir, "hello.shtml"), "w") as f:
            f.write('<!--#echo var="DOCUMENT_NAME" --> Hello from hello.shtml\n')

        # --- deflate / FilterChain test data ---
        gz_dir = os.path.join(doc_dir, "filtertest")
        os.makedirs(gz_dir, exist_ok=True)
        gz_path = os.path.join(gz_dir, "hello.txt.gz")
        with gzip.open(gz_path, "wb") as f:
            f.write(b"Good morning, fellow!")

    # --- mod_ext_filter ---------------------------------------------------

    @pytest.mark.skipif(sys.platform == "win32",
                        reason="/usr/bin/grep is not available on Windows")
    def test_filters_005_01(self, env):
        """ExtFilterDefine with grep keeps only matching lines."""
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": """
            ExtFilterDefine grepfilter cmd="/usr/bin/grep crap"
            <Location "/extfiltertest/">
                SetOutputFilter grepfilter
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("http", "test1", "/extfiltertest/hello.txt.crap")
        r = env.curl_get(url)
        assert r.response, "no response"
        assert r.response["status"] == 200
        body = r.response["body"].decode()
        assert "crap not allowed during worktime" in body, \
            f"line containing 'crap' should survive the filter: {body!r}"
        assert "recycling can save the earth" not in body, \
            f"line without 'crap' should be removed by grep: {body!r}"

    # --- mod_include (SSI) ------------------------------------------------

    def test_filters_005_02(self, env):
        """Server-Side Includes expand DOCUMENT_NAME."""
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": """
            <Location "/includestest/">
                Options +Includes
                AddOutputFilter INCLUDES .shtml
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("http", "test1", "/includestest/hello.shtml")
        r = env.curl_get(url)
        assert r.response, "no response"
        assert r.response["status"] == 200
        body = r.response["body"].decode()
        assert "<!--#" not in body, \
            f"SSI directive was not processed: {body!r}"
        assert "Hello from hello.shtml" in body, \
            f"SSI output missing expected text: {body!r}"

    # --- mod_deflate / FilterChain ----------------------------------------

    def test_filters_005_03a(self, env):
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

    def test_filters_005_03b(self, env):
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
