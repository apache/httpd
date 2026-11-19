import pytest

from .env import H2Conf, H2TestEnv

BODY = b"SHOULD-NOT-BE-SENT\n"


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported(), reason="mod_http2 not supported here")
class TestStatusNoBody:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        H2Conf(env, extras={
            "base": [
                "<Location /pre>",
                "    SetHandler aptest-prebuilt",
                "</Location>",
            ]
        }).add_vhost_cgi().install()
        assert env.apache_restart() == 0

    def get(self, env, status, options=None):
        url = env.mkurl("https", "cgi", f"/status_body.py?status={status}")
        r = env.curl_get(url, options=["--http2"] + (options or []))
        assert r.response, f"no response: {r.stderr}"
        assert r.response["header"]["server"], "not an HTTP/2 response"
        return r.response

    # a 205 carries no content, whatever the handler writes
    def test_h2_204_01(self, env):
        r = self.get(env, 205)
        assert r["status"] == 205
        assert r["body"] == b""

    # the same when the handler writes its content in several flushed parts
    def test_h2_204_05(self, env):
        url = env.mkurl("https", "cgi", "/status_body.py?status=205&parts=3")
        r = env.curl_get(url, options=["--http2"])
        assert r.response["status"] == 205
        assert r.response["body"] == b""

    # 204 and 304 stay without content
    @pytest.mark.parametrize("code", [204, 304])
    def test_h2_204_02(self, env, code):
        r = self.get(env, code)
        assert r["status"] == code
        assert r["body"] == b""

    # other 2xx statuses still carry the body
    @pytest.mark.parametrize("code", [200, 201, 202])
    def test_h2_204_03(self, env, code):
        r = self.get(env, code)
        assert r["status"] == code
        assert r["body"] == BODY

    # the connection is still usable after a 205
    def test_h2_204_04(self, env):
        urls = [env.mkurl("https", "cgi", f"/status_body.py?status={s}")
                for s in (205, 200, 205, 200)]
        r = env.curl_raw(urls, options=["--http2"], no_stdout_list=True)
        statuses = []
        resp = r.response
        while resp:
            statuses.append(resp["status"])
            resp = resp.get("previous")
        assert statuses[::-1] == [205, 200, 205, 200]
        # all content is from the two 200 responses
        assert r.stdout == (BODY * 2).decode()

    # the same when the response is a final response bucket written by the
    # handler itself
    @pytest.mark.parametrize("code", [204, 205, 304])
    def test_h2_204_06(self, env, code):
        url = env.mkurl("https", "cgi", f"/pre?status={code}")
        r = env.curl_get(url, options=["--http2"])
        assert r.response["status"] == code
        assert r.response["body"] == b""
