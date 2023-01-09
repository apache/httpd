import pytest

from pyhttpd.env import HttpdTestEnv
from .env import H2Conf


class TestRfc9113:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        H2Conf(env).add_vhost_test1().install()
        assert env.apache_restart() == 0

    # by default, we accept leading/trailing ws in request fields
    def test_h2_203_01_ws_ignore(self, env):
        url = env.mkurl("https", "test1", "/")
        r = env.curl_get(url, options=['-H', 'trailing-space: must not  '])
        assert r.exit_code == 0, f'curl output: {r.stderr}'
        assert r.response["status"] == 200, f'curl output: {r.stdout}'
        r = env.curl_get(url, options=['-H', 'trailing-space: must not\t'])
        assert r.exit_code == 0, f'curl output: {r.stderr}'
        assert r.response["status"] == 200, f'curl output: {r.stdout}'

    # response header are also handled, but we strip ws before sending
    @pytest.mark.parametrize(["hvalue", "expvalue", "status"], [
        ['"123"', '123', 200],
        ['"123 "', '123', 200],       # trailing space stripped
        ['"123\t"', '123', 200],     # trailing tab stripped
        ['" 123"', '123', 200],        # leading space is stripped
        ['"          123"', '123', 200],  # leading spaces are stripped
        ['"\t123"', '123', 200],       # leading tab is stripped
        ['"expr=%{unescape:123%0A 123}"', '', 500],  # illegal char
        ['" \t "', '', 200],          # just ws
    ])
    def test_h2_203_02(self, env, hvalue, expvalue, status):
        hname = 'ap-test-007'
        conf = H2Conf(env, extras={
            f'test1.{env.http_tld}': [
                '<Location /index.html>',
                f'Header add {hname} {hvalue}',
                '</Location>',
            ]
        })
        conf.add_vhost_test1(proxy_self=True)
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "test1", "/index.html")
        r = env.curl_get(url, options=['--http2'])
        if status == 500 and r.exit_code != 0:
            # in 2.4.x we fail late on control chars in a response
            # and RST_STREAM. That's also ok
            return
        assert r.response["status"] == status
        if int(status) < 400:
            assert r.response["header"][hname] == expvalue

