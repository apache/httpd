import pytest

from .env import H2Conf


class TestUpgrade:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        H2Conf(env).add_vhost_test1().add_vhost_test2().add_vhost_noh2(
        ).start_vhost(domains=[f"test3.{env.http_tld}"], port=env.https_port, doc_root="htdocs/test1"
        ).add(
            """
            Protocols h2 http/1.1
            Header unset Upgrade"""
        ).end_vhost(
        ).start_vhost(domains=[f"test1b.{env.http_tld}"], port=env.http_port, doc_root="htdocs/test1"
        ).add(
            """
            Protocols h2c http/1.1
            H2Upgrade off
            <Location /006.html>
                H2Upgrade on
            </Location>"""
        ).end_vhost(
        ).install()
        assert env.apache_restart() == 0

    # accessing http://test1, will not try h2 and advertise h2 in the response
    def test_h2_103_01(self, env):
        url = env.mkurl("http", "test1", "/index.html")
        r = env.curl_get(url)
        assert 0 == r.exit_code
        assert r.response
        assert "upgrade" in r.response["header"]
        assert "h2c" == r.response["header"]["upgrade"]
        
    # accessing http://noh2, will not advertise, because noh2 host does not have it enabled
    def test_h2_103_02(self, env):
        url = env.mkurl("http", "noh2", "/index.html")
        r = env.curl_get(url)
        assert 0 == r.exit_code
        assert r.response
        assert "upgrade" not in r.response["header"]
        
    # accessing http://test2, will not advertise, because h2 has less preference than http/1.1
    def test_h2_103_03(self, env):
        url = env.mkurl("http", "test2", "/index.html")
        r = env.curl_get(url)
        assert 0 == r.exit_code
        assert r.response
        assert "upgrade" not in r.response["header"]

    # accessing https://noh2, will not advertise, because noh2 host does not have it enabled
    def test_h2_103_04(self, env):
        url = env.mkurl("https", "noh2", "/index.html")
        r = env.curl_get(url)
        assert 0 == r.exit_code
        assert r.response
        assert "upgrade" not in r.response["header"]

    # accessing https://test2, will not advertise, because h2 has less preference than http/1.1
    def test_h2_103_05(self, env):
        url = env.mkurl("https", "test2", "/index.html")
        r = env.curl_get(url)
        assert 0 == r.exit_code
        assert r.response
        assert "upgrade" not in r.response["header"]
        
    # accessing https://test1, will advertise h2 in the response
    def test_h2_103_06(self, env):
        url = env.mkurl("https", "test1", "/index.html")
        r = env.curl_get(url, options=["--http1.1"])
        assert 0 == r.exit_code
        assert r.response
        assert "upgrade" in r.response["header"]
        assert "h2" == r.response["header"]["upgrade"]
        
    # accessing https://test3, will not send Upgrade since it is suppressed
    def test_h2_103_07(self, env):
        url = env.mkurl("https", "test3", "/index.html")
        r = env.curl_get(url, options=["--http1.1"])
        assert 0 == r.exit_code
        assert r.response
        assert "upgrade" not in r.response["header"]

    # upgrade to h2c for a request, where h2c is preferred
    def test_h2_103_20(self, env):
        url = env.mkurl("http", "test1", "/index.html")
        r = env.nghttp().get(url, options=["-u"])
        assert r.response["status"] == 200

    # upgrade to h2c for a request where http/1.1 is preferred, but the clients upgrade
    # wish is honored nevertheless
    def test_h2_103_21(self, env):
        url = env.mkurl("http", "test2", "/index.html")
        r = env.nghttp().get(url, options=["-u"])
        assert 404 == r.response["status"]

    # ugrade to h2c on a host where h2c is not enabled will fail
    def test_h2_103_22(self, env):
        url = env.mkurl("http", "noh2", "/index.html")
        r = env.nghttp().get(url, options=["-u"])
        assert not r.response

    # ugrade to h2c on a host where h2c is preferred, but Upgrade is disabled
    def test_h2_103_23(self, env):
        url = env.mkurl("http", "test1b", "/index.html")
        r = env.nghttp().get(url, options=["-u"])
        assert not r.response

    # ugrade to h2c on a host where h2c is preferred, but Upgrade is disabled on the server,
    # but allowed for a specific location
    def test_h2_103_24(self, env):
        url = env.mkurl("http", "test1b", "/006.html")
        r = env.nghttp().get(url, options=["-u"])
        assert r.response["status"] == 200
