import pytest

from pyhttpd.backport import not_backported
from pyhttpd.conf import HttpdConf

pytestmark = not_backported("r1410755",
                            "SERVER_PROTOCOL_VERSION ap_expr variables",
                            backported_in="2.4.72")


# The variables do not parse on a server without them, so the restart
# status is checked by each test rather than here.
@pytest.fixture(scope='module')
def restart_rc(env):
    conf = HttpdConf(env, extras={
        'base': """
    ErrorDocument 404 "v=%{SERVER_PROTOCOL_VERSION} major=%{SERVER_PROTOCOL_VERSION_MAJOR} minor=%{SERVER_PROTOCOL_VERSION_MINOR}"
    """
    })
    conf.add_vhost_test1()
    conf.install()
    return env.apache_restart()


class TestExprProtoVersion:

    def get(self, env, restart_rc, options):
        assert restart_rc == 0
        r = env.curl_get(env.mkurl("http", "test1", "/no-such-file"),
                         options=options)
        assert r.response, f"no response: {r.stderr}"
        assert r.response["status"] == 404
        return r.response["body"].decode().strip()

    def test_core_013_01_http11(self, env, restart_rc):
        assert self.get(env, restart_rc, ['--http1.1']) == \
            "v=1001 major=1 minor=1"

    def test_core_013_02_http10(self, env, restart_rc):
        assert self.get(env, restart_rc, ['--http1.0']) == \
            "v=1000 major=1 minor=0"
