import gzip
import os
import sys

import pytest

from pyhttpd.conf import HttpdConf

class TestModExtFilters:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")

        # --- ext_filter test data ---
        ext_dir = os.path.join(doc_dir, "extfiltertest")
        os.makedirs(ext_dir, exist_ok=True)
        with open(os.path.join(ext_dir, "hello.txt.crap"), "w") as f:
            f.write("crap not allowed during worktime\n"
                    "recycling can save the earth\n")

    @pytest.mark.skipif(sys.platform == "win32",
                        reason="/usr/bin/grep is not available on Windows")
    def test_mod_ext_filter_005_01(self, env):
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
