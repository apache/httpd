import pytest

from pyhttpd.env import HttpdTestEnv
from .env import H2Conf


class TestRfc9113:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        H2Conf(env).add_vhost_test1().install()
        assert env.apache_restart() == 0

    # by default, we ignore leading/trailing ws
    # tests with leading ws are not present as curl seems to silently eat those
    def test_h2_203_01_ws_ignore(self, env):
        url = env.mkurl("https", "test1", "/")
        r = env.curl_get(url, options=['-H', 'trailing-space: must not  '])
        assert r.exit_code == 0, f'curl output: {r.stderr}'
        assert r.response["status"] == 200, f'curl output: {r.stdout}'
        r = env.curl_get(url, options=['-H', 'trailing-space: must not\t'])
        assert r.exit_code == 0, f'curl output: {r.stderr}'
        assert r.response["status"] == 200, f'curl output: {r.stdout}'

    # When enabled, leading/trailing make the stream RST
    # tests with leading ws are not present as curl seems to silently eat those
    def test_h2_203_02_ws_reject(self, env):
        if not env.h2load_is_at_least('1.50.0'):
            pytest.skip(f'need nghttp2 >= 1.50.0')
        conf = H2Conf(env)
        conf.add([
            "H2HeaderStrictness rfc9113"
        ])
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "test1", "/")
        r = env.curl_get(url, options=['-H', 'trailing-space: must not  '])
        assert r.exit_code != 0, f'curl output: {r.stderr}'
        r = env.curl_get(url, options=['-H', 'trailing-space: must not\t'])
        assert r.exit_code != 0, f'curl output: {r.stderr}'

