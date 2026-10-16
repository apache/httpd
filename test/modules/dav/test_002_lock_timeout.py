import glob
import os
import re
import pytest

from pyhttpd.conf import HttpdConf


class TestLockTimeout:

    LOCKINFO = ('<?xml version="1.0" encoding="utf-8"?>'
                '<D:lockinfo xmlns:D="DAV:">'
                '<D:lockscope><D:exclusive/></D:lockscope>'
                '<D:locktype><D:write/></D:locktype>'
                '</D:lockinfo>')

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        dav_dir = os.path.join(env.gen_dir, 'dav-lock')
        os.makedirs(dav_dir, exist_ok=True)
        for name in ['a.txt', 'b.txt', 'c.txt', 'd.txt']:
            with open(os.path.join(dav_dir, name), 'w') as fd:
                fd.write('hello\n')
        for fpath in glob.glob(os.path.join(env.gen_dir, 'davlock-timeout*')):
            os.remove(fpath)
        conf = HttpdConf(env, extras={
            'base': f"""
        DavLockDB "{env.gen_dir}/davlock-timeout"
        """,
            f"test1.{env.http_tld}": f"""
        Alias /dav-lock "{dav_dir}"
        <Directory "{dav_dir}">
            Dav On
            Require all granted
        </Directory>
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def _lock(self, env, name: str, timeout: str):
        fpath = os.path.join(env.gen_dir, 'lockinfo.xml')
        with open(fpath, 'w') as fd:
            fd.write(self.LOCKINFO)
        url = env.mkurl("https", "test1", f"/dav-lock/{name}")
        return env.curl_raw(url, options=[
            '-X', 'LOCK', '-H', f'Timeout: {timeout}',
            '-H', 'Content-Type: text/xml', '--data-binary', f'@{fpath}'])

    def _lock_refused(self, env, name: str):
        # a second exclusive lock on a still locked resource is refused
        r = self._lock(env, name, "Second-60")
        env.httpd_error_log.ignore_recent(
            matches=[r'.*Could not LOCK .* due to a failed precondition.*',
                     r'.*Existing lock\(s\) on the requested resource.*'])
        return r.response["status"] == 423

    @staticmethod
    def _timeout(r) -> str:
        m = re.search(r'<D:timeout>([^<]*)</D:timeout>', r.stdout)
        assert m, f'no timeout in LOCK response: {r.stdout}'
        return m.group(1)

    # an ordinary Second-xxx timeout is used as given, and the lock is held
    @pytest.mark.parametrize("name, timeout, low, high", [
        ("a.txt", "Second-600", 590, 600),
        # too large to add to the current time: capped at the RFC 4918
        # maximum of 2^32 - 1 rather than wrapping to an expired lock
        ("b.txt", "Second-9223372036854775807", 4294967285, 4294967295),
        # a malformed value is skipped in favour of the next TimeType
        ("d.txt", "Second-abc, Second-60", 50, 60),
    ])
    def test_dav_002_01(self, env, name, timeout, low, high):
        r = self._lock(env, name, timeout)
        assert r.response["status"] == 200
        m = re.match(r'Second-(\d+)$', self._timeout(r))
        assert m, self._timeout(r)
        assert low <= int(m.group(1)) <= high
        assert self._lock_refused(env, name)

    # a negative timeout is not understood, so the lock is not
    # created already expired
    def test_dav_002_02(self, env):
        r = self._lock(env, "c.txt", "Second--100")
        assert r.response["status"] == 200
        assert self._timeout(r) == "Infinite"
        assert self._lock_refused(env, "c.txt")
