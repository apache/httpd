import pytest

from .env import H2Conf


class TestConditionalHeaders:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        H2Conf(env).add(
            """
            KeepAlive on
            MaxKeepAliveRequests 30
            KeepAliveTimeout 30"""
        ).add_vhost_test1().install()
        assert env.apache_restart() == 0

    # check handling of 'if-modified-since' header
    def test_h2_201_01(self, env):
        url = env.mkurl("https", "test1", "/006/006.css")
        r = env.curl_get(url)
        assert r.response["status"] == 200
        lm = r.response["header"]["last-modified"]
        assert lm
        r = env.curl_get(url, options=["-H", "if-modified-since: %s" % lm])
        assert 304 == r.response["status"]
        r = env.curl_get(url, options=["-H", "if-modified-since: Tue, 04 Sep 2010 11:51:59 GMT"])
        assert r.response["status"] == 200

    # check handling of 'if-none-match' header
    def test_h2_201_02(self, env):
        url = env.mkurl("https", "test1", "/006/006.css")
        r = env.curl_get(url)
        assert r.response["status"] == 200
        etag = r.response["header"]["etag"]
        assert etag
        r = env.curl_get(url, options=["-H", "if-none-match: %s" % etag])
        assert 304 == r.response["status"]
        r = env.curl_get(url, options=["-H", "if-none-match: dummy"])
        assert r.response["status"] == 200
        
    @pytest.mark.skipif(True, reason="304 misses the Vary header in trunk and 2.4.x")
    def test_h2_201_03(self, env):
        url = env.mkurl("https", "test1", "/006.html")
        r = env.curl_get(url, options=["-H", "Accept-Encoding: gzip"])
        assert r.response["status"] == 200
        for h in r.response["header"]:
            print("%s: %s" % (h, r.response["header"][h]))
        lm = r.response["header"]["last-modified"]
        assert lm
        assert "gzip" == r.response["header"]["content-encoding"]
        assert "Accept-Encoding" in r.response["header"]["vary"]
        
        r = env.curl_get(url, options=["-H", "if-modified-since: %s" % lm,
                                       "-H", "Accept-Encoding: gzip"])
        assert 304 == r.response["status"]
        for h in r.response["header"]:
            print("%s: %s" % (h, r.response["header"][h]))
        assert "vary" in r.response["header"]

    # Check if "Keep-Alive" response header is removed in HTTP/2.
    def test_h2_201_04(self, env):
        url = env.mkurl("https", "test1", "/006.html")
        r = env.curl_get(url, options=["--http1.1", "-H", "Connection: keep-alive"])
        assert r.response["status"] == 200
        assert "timeout=30, max=30" == r.response["header"]["keep-alive"]
        r = env.curl_get(url, options=["-H", "Connection: keep-alive"])
        assert r.response["status"] == 200
        assert "keep-alive" not in r.response["header"]
