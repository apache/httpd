import os
import sys
import pytest

from pyhttpd.conf import HttpdConf


class TestDavIfHeader:
    """mod_dav out-of-bounds read/write of zero byte when parsing a
    malformed 'Not' token in the If: header.  The fix should reject
    the malformed header with 400 Bad Request."""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        dav_dir = os.path.join(env.gen_dir, 'dav-if')
        os.makedirs(dav_dir, exist_ok=True)
        with open(os.path.join(dav_dir, "hello.txt"), "w") as f:
            f.write("hello")
        dav_dir_conf = dav_dir.replace('\\', '/')
        lock_db_conf = os.path.join(env.gen_dir, 'davlock-if').replace('\\', '/')
        conf = HttpdConf(env, extras={
            'base': f"""
        DavLockDB "{lock_db_conf}"
        """,
            f"test1.{env.http_tld}": f"""
        Alias /dav-if "{dav_dir_conf}"
        <Directory "{dav_dir_conf}">
            Dav On
            Require all granted
        </Directory>
        LogLevel debug
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    @pytest.mark.skipif(sys.platform == 'win32',
                        reason="crashes Apache child process on Windows")
    def test_dav_003_01(self, env):
        """COPY with truncated 'Not' in If: header should return 400,
        not crash or succeed."""
        url = env.mkurl("http", "test1", "/dav-if/hello.txt")
        dest = env.mkurl("http", "test1", "/dav-if/hello2.txt")
        r = env.curl_raw(url, options=[
            '-X', 'COPY',
            '-H', f'Destination: {dest}',
            '-H', 'Overwrite: T',
            '-H', 'If: (N)',
            '-v',
        ])
        assert r.response is not None
        assert r.response["status"] == 400, \
            f"Malformed If: header should produce 400, got {r.response['status']}"
        env.httpd_error_log.ignore_recent(
            matches=[r'.*Invalid.*If.*header.*', r'.*dav:error.*',
                     r'.*:error\].*'])
