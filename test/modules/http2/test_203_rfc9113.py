import pytest
from typing import List, Optional

from pyhttpd.env import HttpdTestEnv
from .env import H2Conf, H2TestEnv


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported(), reason="mod_http2 not supported here")
class TestRfc9113:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        H2Conf(env).add_vhost_test1().install()
        assert env.apache_restart() == 0
        # test_h2_203_02 sends a response header with an illegal char on
        # purpose; httpd rightly rejects it with AH02430 and RST_STREAMs the
        # request. With HTTP/2 that error is emitted *late*, during stream
        # teardown, and a single case can produce several AH02430 lines spread
        # over time -- so a per-case ignore_recent() races the stragglers,
        # which then surface in a later test's check_error_log() (the timing,
        # and thus which MPM trips, varies with sync vs async h2 handoff).
        # AH02430 is only ever produced here intentionally, so ignore it for
        # the whole class; restore the prior set afterwards so it does not leak.
        env.httpd_error_log.add_ignored_lognos(['AH02430'])
        yield
        env.httpd_error_log.remove_ignored_lognos(['AH02430'])

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
    @pytest.mark.parametrize(["hvalue", "expvalue", "status", "lognos"], [
        ['"123"', '123', 200, None],
        ['"123 "', '123', 200, None],       # trailing space stripped
        ['"123\t"', '123', 200, None],     # trailing tab stripped
        ['" 123"', '123', 200, None],        # leading space is stripped
        ['"          123"', '123', 200, None],  # leading spaces are stripped
        ['"\t123"', '123', 200, None],       # leading tab is stripped
        ['"expr=%{unescape:123%0A 123}"', '', 500, ["AH02430"]],  # illegal char
        ['" \t "', '', 200, None],          # just ws
    ])
    def test_h2_203_02(self, env, hvalue, expvalue, status, lognos: Optional[List[str]]):
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
        #
        if lognos is not None:
            env.httpd_error_log.ignore_recent(lognos = lognos)

