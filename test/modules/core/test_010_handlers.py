import os
import pytest

from pyhttpd.conf import HttpdConf


class TestHandlers:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        conf = HttpdConf(env, extras={
            'base': f"""
        <Location /our-server-info>
            SetHandler server-info
            Require all granted
        </Location>

        <Location /our-server-status>
            SetHandler server-status
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
    def test_core_010_01(self, env):
        url = env.mkurl("http", "test1", "/our-server-info")
        r = env.curl_get(url)
        assert r.response, f"no response: {r.stderr}"
        assert r.response["status"] == 200
        body = r.response["body"].decode()
        assert "Apache Server Information" in body

    # mod_info: verify ?list query returns module list
    def test_core_010_02(self, env):
        url = env.mkurl("http", "test1", "/our-server-info?list")
        r = env.curl_get(url)
        assert r.response, f"no response: {r.stderr}"
        assert r.response["status"] == 200
        body = r.response["body"].decode()
        assert "Server Module List" in body

    # mod_status: verify basic server-status page
    def test_core_010_03(self, env):
        url = env.mkurl("http", "test1", "/our-server-status")
        r = env.curl_get(url)
        assert r.response, f"no response: {r.stderr}"
        assert r.response["status"] == 200
        body = r.response["body"].decode()
        assert "Apache Server Status" in body

    # mod_status: verify extended status shows worker information
    def test_core_010_04(self, env):
        # Reconfigure with ExtendedStatus On
        conf = HttpdConf(env, extras={
            'base': f"""
        ExtendedStatus On

        <Location /our-server-status>
            SetHandler server-status
            Require all granted
        </Location>
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

        url = env.mkurl("http", "test1", "/our-server-status")
        r = env.curl_get(url)
        assert r.response, f"no response: {r.stderr}"
        assert r.response["status"] == 200
        body = r.response["body"].decode()
        assert "requests currently being processed" in body or \
               "idle workers" in body

    # mod_actions: verify Action directive routes request through CGI handler
    def test_core_010_05(self, env):
        # Re-apply the full config (010_04 changed it)
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        conf = HttpdConf(env, extras={
            'base': f"""
        <Location /our-server-info>
            SetHandler server-info
            Require all granted
        </Location>
        <Location /our-server-status>
            SetHandler server-status
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

        url = env.mkurl("http", "test1", "/actionstest/dummy.chtml")
        r = env.curl_get(url)
        assert r.response, f"no response: {r.stderr}"
        assert r.response["status"] == 200
        body = r.response["body"].decode()
        assert "this file was processed" in body

    # mod_asis: verify send-as-is handler sends raw response
    def test_core_010_06(self, env):
        url = env.mkurl("http", "test1", "/asistest/example.ahtml")
        r = env.curl_get(url)
        assert r.response, f"no response: {r.stderr}"
        assert r.response["status"] == 301
