import pytest

from .env import H2Conf, H2TestEnv


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestConnReuse:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        H2Conf(env).add_vhost_noh2().add_vhost_test1().add_vhost_cgi().install()
        assert env.apache_restart() == 0

    # make sure the protocol selection on the different hosts work as expected
    def test_h2_100_01(self, env):
        # this host defaults to h2, but we can request h1
        url = env.mkurl("https", "cgi", "/hello.py")
        assert "2" == env.curl_protocol_version( url )
        assert "1.1" == env.curl_protocol_version( url, options=[ "--http1.1" ] )
        
        # this host does not enable h2, it always falls back to h1
        url = env.mkurl("https", "noh2", "/hello.py")
        assert "1.1" == env.curl_protocol_version( url )
        assert "1.1" == env.curl_protocol_version( url, options=[ "--http2" ] )

    # access a ServerAlias, after using ServerName in SNI
    def test_h2_100_02(self, env):
        url = env.mkurl("https", "cgi", "/hello.py")
        hostname = ("cgi-alias.%s" % env.http_tld)
        r = env.curl_get(url, 5, options=["-H", f"Host: {hostname}"])
        assert r.response["status"] == 200
        assert "HTTP/2" == r.response["protocol"]
        assert hostname == r.response["json"]["host"]

    # access another vhost, after using ServerName in SNI, that uses same SSL setup
    def test_h2_100_03(self, env):
        url = env.mkurl("https", "cgi", "/")
        hostname = ("test1.%s" % env.http_tld)
        r = env.curl_get(url, 5, options=[ "-H", "Host:%s" % hostname ])
        assert r.response["status"] == 200
        assert "HTTP/2" == r.response["protocol"]
        assert "text/html" == r.response["header"]["content-type"]

    # access another vhost, after using ServerName in SNI, 
    # that has different SSL certificate. This triggers a 421 (misdirected request) response.
    def test_h2_100_04(self, env):
        url = env.mkurl("https", "cgi", "/hello.py")
        hostname = ("noh2.%s" % env.http_tld)
        r = env.curl_get(url, 5, options=[ "-H", "Host:%s" % hostname ])
        assert 421 == r.response["status"]

    # access an unknown vhost, after using ServerName in SNI
    def test_h2_100_05(self, env):
        url = env.mkurl("https", "cgi", "/hello.py")
        hostname = ("unknown.%s" % env.http_tld)
        r = env.curl_get(url, 5, options=[ "-H", "Host:%s" % hostname ])
        assert 421 == r.response["status"]
