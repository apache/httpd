import pytest

from .env import H2Conf


class TestStore:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = H2Conf(env)
        conf.add_vhost_test1()
        conf.add_vhost_test2()
        conf.install()
        assert env.apache_restart() == 0

    # check that we see the correct documents when using the test1 server name over http:
    def test_h2_002_01(self, env):
        url = env.mkurl("http", "test1", "/alive.json")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert "HTTP/1.1" == r.response["protocol"]
        assert r.response["json"]["alive"] is True
        assert r.response["json"]["host"] == "test1"

    # check that we see the correct documents when using the test1 server name over https:
    def test_h2_002_02(self, env):
        url = env.mkurl("https", "test1", "/alive.json")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert r.response["json"]["alive"] is True
        assert "test1" == r.response["json"]["host"]
        assert r.response["header"]["content-type"] == "application/json"

    # enforce HTTP/1.1
    def test_h2_002_03(self, env):
        url = env.mkurl("https", "test1", "/alive.json")
        r = env.curl_get(url, 5, options=["--http1.1"])
        assert r.response["status"] == 200
        assert r.response["protocol"] == "HTTP/1.1"

    # enforce HTTP/2
    def test_h2_002_04(self, env):
        url = env.mkurl("https", "test1", "/alive.json")
        r = env.curl_get(url, 5, options=["--http2"])
        assert r.response["status"] == 200
        assert r.response["protocol"] == "HTTP/2"

    # default is HTTP/2 on this host
    def test_h2_002_04b(self, env):
        url = env.mkurl("https", "test1", "/alive.json")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert r.response["protocol"] == "HTTP/2"
        assert r.response["json"]["host"] == "test1"

    # although, without ALPN, we cannot select it
    def test_h2_002_05(self, env):
        url = env.mkurl("https", "test1", "/alive.json")
        r = env.curl_get(url, 5, options=["--no-alpn"])
        assert r.response["status"] == 200
        assert r.response["protocol"] == "HTTP/1.1"
        assert r.response["json"]["host"] == "test1"

    # default is HTTP/1.1 on the other
    def test_h2_002_06(self, env):
        url = env.mkurl("https", "test2", "/alive.json")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert r.response["protocol"] == "HTTP/1.1"
        assert r.response["json"]["host"] == "test2"
