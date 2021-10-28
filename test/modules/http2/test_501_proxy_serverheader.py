import pytest

from .env import H2Conf


class TestStore:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
                "Header unset Server",
                "Header always set Server cgi",
            ]
        })
        conf.add_vhost_cgi(proxy_self=True, h2proxy_self=False)
        conf.install()
        assert env.apache_restart() == 0

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    def test_h2_501_01(self, env):
        url = env.mkurl("https", "cgi", "/proxy/hello.py")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert "HTTP/1.1" == r.response["json"]["protocol"]
        assert "" == r.response["json"]["https"]
        assert "" == r.response["json"]["ssl_protocol"]
        assert "" == r.response["json"]["h2"]
        assert "" == r.response["json"]["h2push"]
        assert "cgi" == r.response["header"]["server"]
