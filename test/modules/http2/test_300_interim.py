import pytest

from .env import H2Conf, H2TestEnv


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestInterimResponses:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        H2Conf(env).add_vhost_test1().add_vhost_cgi().install()
        assert env.apache_restart() == 0

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    # check that we normally do not see an interim response
    def test_h2_300_01(self, env):
        url = env.mkurl("https", "test1", "/index.html")
        r = env.curl_post_data(url, 'XYZ')
        assert r.response["status"] == 200
        assert "previous" not in r.response

    # check that we see an interim response when we ask for it
    def test_h2_300_02(self, env):
        url = env.mkurl("https", "cgi", "/echo.py")
        r = env.curl_post_data(url, 'XYZ', options=["-H", "expect: 100-continue"])
        assert r.response["status"] == 200
        assert "previous" in r.response
        assert 100 == r.response["previous"]["status"] 

    # check proper answer on unexpected
    def test_h2_300_03(self, env):
        url = env.mkurl("https", "cgi", "/echo.py")
        r = env.curl_post_data(url, 'XYZ', options=["-H", "expect: the-unexpected"])
        assert 417 == r.response["status"]
        assert "previous" not in r.response
