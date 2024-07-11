import pytest

from .env import H1Conf


class TestBasicAlive:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        H1Conf(env).add_vhost_test1().install()
        assert env.apache_restart() == 0

    # we expect to see the document from the generic server
    def test_h1_001_01(self, env):
        url = env.mkurl("https", "test1", "/alive.json")
        r = env.curl_get(url, 5)
        assert r.exit_code == 0, r.stderr + r.stdout
        assert r.response["json"]
        assert r.response["json"]["alive"] is True
        assert r.response["json"]["host"] == "test1"
