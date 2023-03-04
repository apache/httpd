import pytest

from .conf import TlsTestConf


class TestApache:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        TlsTestConf(env=env).install()
        assert env.apache_restart() == 0

    def test_tls_01_apache_http(self, env):
        assert env.is_live(env.http_base_url)
