import pytest

from h2_conf import HttpdConf


class TestStore:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        HttpdConf(env).add_vhost_test1().install()
        assert env.apache_restart() == 0

    # we expect to see the document from the generic server
    def test_001_01(self, env):
        r = env.curl_get(f"https://{env.domain_test1}:{env.https_port}/alive.json", 5)
        assert r.exit_code == 0, r.stderr + r.stdout
        assert r.response["json"]
        assert True == r.response["json"]["alive"]
        assert "test1" == r.response["json"]["host"]

    # we expect to see the document from the generic server
    def test_001_02(self, env):
        r = env.curl_get(f"https://{env.domain_test1}:{env.https_port}/alive.json", 5)
        assert r.exit_code == 0, r.stderr
        assert r.response["json"]
        assert True == r.response["json"]["alive"]
        assert "test1" == r.response["json"]["host"]

