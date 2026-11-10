import os
import pytest

from pyhttpd.conf import HttpdConf


class TestActionsHandlers:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        conf = HttpdConf(env)
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    # mod_actions: verify Action directive routes request through CGI handler
    def test_core_005_01_routes_req_thru_cgi_handler(self, env):
        # Re-apply the full config (010_04 changed it)
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
        <Directory "{doc_dir}/cgi">
            Options +ExecCGI
            AddHandler cgi-script .py
        </Directory>
        Action html-cgi /cgi/handler.py
        AddHandler html-cgi .chtml
        AddHandler send-as-is .ahtml
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

        url = env.mkurl("http", "test1", "/actionstest/dummy.chtml")
        r = env.curl_get(url)
        assert r.response, f"no response: {r.stderr}"
        assert r.response["status"] == 200
        body = r.response["body"].decode()
        assert "this file was processed" in body
