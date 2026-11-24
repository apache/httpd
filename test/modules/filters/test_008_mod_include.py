import gzip
import os
import sys

import pytest

from pyhttpd.conf import HttpdConf

class TestModIncludeFilters:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")

        ssi_dir = os.path.join(doc_dir, "includestest")
        os.makedirs(ssi_dir, exist_ok=True)
        with open(os.path.join(ssi_dir, "hello.shtml"), "w") as f:
            f.write('<!--#echo var="DOCUMENT_NAME" --> Hello from hello.shtml\n')

    def test_mod_include_008_01(self, env):
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

    