import os
import pytest

from pyhttpd.conf import HttpdConf


class TestInfoHandlers:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        conf = HttpdConf(env, extras={
            'base': f"""
        <Location /our-server-info>
            SetHandler server-info
            Require all granted
        </Location>
        """,
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

    # mod_info: verify server-info handler returns server information page
    def test_core_006_01_server_returns_info_page(self, env):
        url = env.mkurl("http", "test1", "/our-server-info")
        r = env.curl_get(url)
        assert r.response, f"no response: {r.stderr}"
        assert r.response["status"] == 200
        body = r.response["body"].decode()
        assert "Apache Server Information" in body

    # mod_info: verify ?list query returns module list
    def test_core_006_02_server_returns_modoule_list(self, env):
        url = env.mkurl("http", "test1", "/our-server-info?list")
        r = env.curl_get(url)
        assert r.response, f"no response: {r.stderr}"
        assert r.response["status"] == 200
        body = r.response["body"].decode()
        assert "Server Module List" in body
