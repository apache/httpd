import pytest

from h2_conf import HttpdConf


class TestStore:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        HttpdConf(env).add_vhost_test1().add_vhost_test2().install()
        assert env.apache_restart() == 0

    # check that we see the correct documents when using the test1 server name over http:
    def test_002_01(self, env):
        url = env.mkurl("http", "test1", "/alive.json")
        r = env.curl_get(url, 5)
        assert 200 == r.response["status"]
        assert "HTTP/1.1" == r.response["protocol"]
        assert True == r.response["json"]["alive"]
        assert "test1" == r.response["json"]["host"]

    # check that we see the correct documents when using the test1 server name over https:
    def test_002_02(self, env):
        url = env.mkurl("https", "test1", "/alive.json")
        r = env.curl_get(url, 5)
        assert 200 == r.response["status"]
        assert r.response["json"]["alive"] is True
        assert "test1" == r.response["json"]["host"]
        assert "application/json" == r.response["header"]["content-type"]

    # enforce HTTP/1.1
    def test_002_03(self, env):
        url = env.mkurl("https", "test1", "/alive.json")
        r = env.curl_get(url, 5, [ "--http1.1" ])
        assert 200 == r.response["status"]
        assert "HTTP/1.1" == r.response["protocol"]

    # enforce HTTP/2
    def test_002_04(self, env):
        url = env.mkurl("https", "test1", "/alive.json")
        r = env.curl_get(url, 5, [ "--http2" ])
        assert 200 == r.response["status"]
        assert "HTTP/2" == r.response["protocol"]

    # default is HTTP/2 on this host
    def test_002_04b(self, env):
        url = env.mkurl("https", "test1", "/alive.json")
        r = env.curl_get(url, 5)
        assert 200 == r.response["status"]
        assert "HTTP/2" == r.response["protocol"]
        assert "test1" == r.response["json"]["host"]

    # although, without ALPN, we cannot select it
    def test_002_05(self, env):
        url = env.mkurl("https", "test1", "/alive.json")
        r = env.curl_get(url, 5, [ "--no-alpn" ])
        assert 200 == r.response["status"]
        assert "HTTP/1.1" == r.response["protocol"]
        assert "test1" == r.response["json"]["host"]

    # default is HTTP/1.1 on the other
    def test_002_06(self, env):
        url = env.mkurl("https", "test2", "/alive.json")
        r = env.curl_get(url, 5)
        assert 200 == r.response["status"]
        assert "HTTP/1.1" == r.response["protocol"]
        assert "test2" == r.response["json"]["host"]

