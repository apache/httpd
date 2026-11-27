import pytest

from pyhttpd.conf import HttpdConf


class TestErrorText505:

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": "Redirect 505 /v505",
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    # The 505 error page says why the request failed (RFC 9110, section
    # 15.6.6), not that the server had an internal error.
    def test_core_017_01_505_error_text(self, env):
        url = env.mkurl("http", "test1", "/v505")
        r = env.curl_get(url)
        assert r.response["status"] == 505
        body = r.response["body"].decode()
        assert "does not support the version of HTTP" in body, body
        assert "internal error" not in body, body
