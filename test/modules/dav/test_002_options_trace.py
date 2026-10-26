import os

import pytest

from pyhttpd.backport import not_backported
from pyhttpd.conf import HttpdConf

DAV_METHODS = {"OPTIONS", "GET", "HEAD", "POST", "DELETE", "PROPFIND",
               "PROPPATCH", "COPY", "MOVE", "LOCK", "UNLOCK"}


def _setup(env, trace):
    dav_dir = os.path.join(env.gen_dir, 'dav')
    os.makedirs(os.path.join(dav_dir, 'col'), exist_ok=True)
    with open(os.path.join(dav_dir, 'file.txt'), 'w') as fd:
        fd.write('hello\n')
    conf = HttpdConf(env, extras={
        'base': f"""
        DavLockDB "{env.gen_dir}/davlock"
        TraceEnable {trace}
        """,
        f"test1.{env.http_tld}": f"""
        Alias /dav "{dav_dir}"
        <Directory "{dav_dir}">
            Dav On
            Require all granted
        </Directory>
        """,
    })
    conf.add_vhost_test1()
    conf.install()
    assert env.apache_restart() == 0


def _request(env, method, path):
    r = env.curl_raw(env.mkurl("https", "test1", path),
                     options=['-X', method])
    assert r.response, f"no response: {r.stderr}"
    allow = r.response["header"].get("allow", "")
    return r.response["status"], {m.strip() for m in allow.split(',') if m.strip()}


@not_backported("r1939146", "DAV OPTIONS Allow honouring TraceEnable")
class TestOptionsTraceDisabled:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        _setup(env, "off")

    # TRACE is not offered while the server refuses it
    @pytest.mark.parametrize("path", ["/dav/file.txt", "/dav/col/"])
    def test_dav_002_001(self, env, path):
        status, allow = _request(env, "OPTIONS", path)
        assert status == 200
        assert "TRACE" not in allow, f"Allow: {allow}"
        assert DAV_METHODS <= allow, f"Allow: {allow}"

    def test_dav_002_002(self, env):
        assert _request(env, "TRACE", "/dav/file.txt")[0] == 405


class TestOptionsTraceEnabled:

    @pytest.fixture(autouse=True, scope='class',
                    params=["on", "extended"])
    def _class_scope(self, env, request):
        _setup(env, request.param)

    # unchanged: TRACE is offered and works
    @pytest.mark.parametrize("path", ["/dav/file.txt", "/dav/col/"])
    def test_dav_002_101(self, env, path):
        status, allow = _request(env, "OPTIONS", path)
        assert status == 200
        assert (DAV_METHODS | {"TRACE"}) <= allow, f"Allow: {allow}"

    def test_dav_002_102(self, env):
        assert _request(env, "TRACE", "/dav/file.txt")[0] == 200
