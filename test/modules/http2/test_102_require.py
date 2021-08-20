import pytest

from h2_conf import HttpdConf


class TestStore:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env).start_vhost(env.https_port, "ssl", with_ssl=True)
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
        env.mkpath("%s/htdocs/ssl-client-verify" % env.server_dir)
        assert env.apache_restart() == 0

    def test_102_01(self, env):
        url = env.mkurl("https", "ssl", "/h2only.html")
        r = env.curl_get(url)
        assert 0 == r.exit_code
        assert r.response
        assert 404 == r.response["status"]
        
    def test_102_02(self, env):
        url = env.mkurl("https", "ssl", "/noh2.html")
        r = env.curl_get(url)
        assert 0 == r.exit_code
        assert r.response
        assert 403 == r.response["status"]
