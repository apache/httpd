import pytest

from .env import H2Conf


class TestRequire:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        domain = f"ssl.{env.http_tld}"
        conf = H2Conf(env)
        conf.start_vhost(domains=[domain], port=env.https_port)
        conf.add("""
              Protocols h2 http/1.1
              SSLOptions +StdEnvVars
              <Location /h2only.html>
                Require expr \"%{HTTP2} == 'on'\"
              </Location>
              <Location /noh2.html>
                Require expr \"%{HTTP2} == 'off'\"
              </Location>""")
        conf.end_vhost()
        conf.install()
        # the dir needs to exists for the configuration to have effect
        env.mkpath(f"{env.server_dir}/htdocs/ssl-client-verify")
        assert env.apache_restart() == 0

    def test_h2_102_01(self, env):
        url = env.mkurl("https", "ssl", "/h2only.html")
        r = env.curl_get(url)
        assert 0 == r.exit_code
        assert r.response
        assert 404 == r.response["status"]
        
    def test_h2_102_02(self, env):
        url = env.mkurl("https", "ssl", "/noh2.html")
        r = env.curl_get(url)
        assert 0 == r.exit_code
        assert r.response
        assert 403 == r.response["status"]
