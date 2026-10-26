import pytest

from pyhttpd.conf import HttpdConf

class TestCGIEnvVars:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env, extras={
            'base': f"""
        <Directory "{env.gen_dir}">
            AllowOverride None
            Options +ExecCGI
        </Directory>
        SetEnv REQUEST-METHOD OVERRIDDEN
        SetEnv QUERY.STRING OVERRIDDEN
        """,
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0

    def test_cgi_003_01(self, env):
        """
        CVE-2025-65082:
        Configuration-defined env vars must not override
        server-calculated CGI env vars.
        """
        url = env.mkurl("http", "cgi", "/env_parameters.py?x=123")
        r = env.curl_get(url)
        assert r.response["status"] == 200
        assert r.response["json"]["REQUEST_METHOD"] == "GET"
        assert r.response["json"]["QUERY_STRING"] == "x=123"
