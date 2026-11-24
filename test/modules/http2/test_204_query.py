import pytest

from .env import H2Conf, H2TestEnv


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported(), reason="mod_http2 not supported here")
class TestQuery:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = H2Conf(env)
        conf.add_vhost_cgi(proxy_self=True, h2proxy_self=True).install()
        assert env.apache_restart() == 0

    def _query(self, env, path, body, ctype="application/jsonpath"):
        url = env.mkurl("https", "cgi", path)
        options = ["-X", "QUERY", "--data-binary", body,
                   "-H", f"Content-Type: {ctype}" if ctype else "Content-Type:"]
        return env.curl_raw([url], options=options)

    # QUERY content reaches the CGI over HTTP/2 (RFC 10008)
    @pytest.mark.parametrize("path", [
        "/echo.py", "/proxy/echo.py", "/h2proxy/echo.py",
    ])
    def test_h2_204_01(self, env, path):
        body = '$..[?@.status=="Rejected"]["doc-id"]'
        r = self._query(env, path, body)
        assert r.exit_code == 0, f"{r}"
        assert r.response["protocol"] == "HTTP/2"
        assert r.response["status"] == 200
        assert r.response["body"] == body.encode()

    # a QUERY without Content-Type fails on HTTP/2 as on HTTP/1.1
    def test_h2_204_02(self, env):
        r = self._query(env, "/echo.py", "q=1", ctype=None)
        assert r.exit_code == 0, f"{r}"
        assert r.response["protocol"] == "HTTP/2"
        assert r.response["status"] == 400
