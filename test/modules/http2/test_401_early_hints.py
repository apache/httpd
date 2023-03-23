import pytest

from .env import H2Conf, H2TestEnv


# The push tests depend on "nghttp"
@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestEarlyHints:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        H2Conf(env).start_vhost(domains=[f"hints.{env.http_tld}"],
                                port=env.https_port, doc_root="htdocs/test1"
        ).add("""
        H2EarlyHints on
        RewriteEngine on
        RewriteRule ^/006-(.*)?\\.html$ /006.html
        <Location /006-hints.html>
            H2PushResource "/006/006.css" critical
        </Location>
        <Location /006-nohints.html>
            Header add Link "</006/006.css>;rel=preload"
        </Location>
        """).end_vhost(
        ).install()
        assert env.apache_restart() == 0

    # H2EarlyHints enabled in general, check that it works for H2PushResource
    def test_h2_401_31(self, env, repeat):
        url = env.mkurl("https", "hints", "/006-hints.html")
        r = env.nghttp().get(url)
        assert r.response["status"] == 200
        promises = r.results["streams"][r.response["id"]]["promises"]
        assert 1 == len(promises)
        early = r.response["previous"]
        assert early
        assert 103 == int(early["header"][":status"])
        assert early["header"]["link"]

    # H2EarlyHints enabled in general, but does not trigger on added response headers
    def test_h2_401_32(self, env, repeat):
        url = env.mkurl("https", "hints", "/006-nohints.html")
        r = env.nghttp().get(url)
        assert r.response["status"] == 200
        promises = r.results["streams"][r.response["id"]]["promises"]
        assert 1 == len(promises)
        assert "previous" not in r.response
