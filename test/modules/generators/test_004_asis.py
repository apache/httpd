import os
import pytest

from pyhttpd.conf import HttpdConf


class TestAsisHandlers:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
        <Directory "{doc_dir}/cgi">
            Options +ExecCGI
            AddHandler cgi-script .py
        </Directory>
        AddHandler html-cgi .chtml
        AddHandler send-as-is .ahtml
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    # mod_asis: verify send-as-is handler sends raw response
    def test_core_004_01_handler_sends_raw_response(self, env):
        url = env.mkurl("http", "test1", "/asistest/example.ahtml")
        r = env.curl_get(url)
        assert r.response, f"no response: {r.stderr}"
        assert r.response["status"] == 301