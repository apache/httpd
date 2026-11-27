import glob
import http.client
import os
import re
import time

import pytest

from pyhttpd.conf import HttpdConf

LOCK_BODY = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<D:lockinfo xmlns:D="DAV:">'
    '<D:lockscope><D:exclusive/></D:lockscope>'
    '<D:locktype><D:write/></D:locktype>'
    '</D:lockinfo>'
)


# BZ 65788: dav_get_timeout_string() in modules/dav/main/util.c parsed a
# "Timeout: Second-<N>" header with atol(), which has no overflow
# detection. A large enough digit string overflows it, and the later
# "now + expires" addition overflows time_t too, so the lock ends up
# stored with a nonsensical (already-expired) timeout instead of the
# large-but-finite one the client asked for -- a LOCK request that looks
# successful (200, a valid Lock-Token) silently grants a lock that is
# already expired.
class TestLockTimeoutOverflow:

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        dav_dir = os.path.join(env.gen_dir, 'dav-timeout-overflow')
        os.makedirs(dav_dir, exist_ok=True)
        for name in ('file1.txt', 'file2.txt', 'file3.txt', 'file4.txt'):
            with open(os.path.join(dav_dir, name), 'w') as fd:
                fd.write('hello\n')

        # the locks outlive the server: file1.txt stays locked for 2^32-1
        # seconds, so a lock database left by an earlier run answers 423
        for f in glob.glob(f"{env.gen_dir}/davlock-timeout-overflow*"):
            os.remove(f)

        conf = HttpdConf(env, extras={
            'base': f"""
        DavLockDB "{env.gen_dir}/davlock-timeout-overflow"
        """,
            f"test1.{env.http_tld}": f"""
        Alias /dav-timeout-overflow "{dav_dir}"
        <Directory "{dav_dir}">
            Dav On
            Require all granted
        </Directory>
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def _lock(self, env, path, timeout_hdr):
        url = env.mkurl("https", "test1", path)
        return env.curl_raw(url, options=[
            '-X', 'LOCK', '-H', f'Timeout: {timeout_hdr}',
            '-H', 'Content-Type: text/xml', '--data-binary', LOCK_BODY])

    # an overflowing Second- value must not silently collapse to an
    # already-expired (or otherwise nonsensical) timeout; it is clamped
    # to the RFC 4918 TimeOut maximum of 2^32 - 1 instead
    def test_dav_004_01(self, env):
        r = self._lock(env, "/dav-timeout-overflow/file1.txt",
                       "Second-99999999999999999999999999999999")
        assert r.response["status"] == 200, r.response
        m = re.search(r'<D:timeout>([^<]*)</D:timeout>', r.stdout)
        assert m, f"no <D:timeout> in response: {r.stdout}"
        # a second may tick between the LOCK and its response
        assert m.group(1) in ("Second-4294967295", "Second-4294967294"), \
            f"timeout: {m.group(1)}"

    # an ordinary, in-range timeout request is unaffected
    def test_dav_004_02(self, env):
        r = self._lock(env, "/dav-timeout-overflow/file2.txt", "Second-600")
        assert r.response["status"] == 200, r.response
        m = re.search(r'<D:timeout>([^<]*)</D:timeout>', r.stdout)
        assert m, f"no <D:timeout> in response: {r.stdout}"
        assert m.group(1) in ("Second-600", "Second-599"), \
            f"timeout: {m.group(1)}"

    # a Second- value with no digits at all parses the same way atol()
    # already did (0, not an error), same as before this fix: an
    # immediately-expired lock, not Infinite
    def test_dav_004_03(self, env):
        r = self._lock(env, "/dav-timeout-overflow/file3.txt",
                       "Second-notanumber")
        assert r.response["status"] == 200, r.response
        m = re.search(r'<D:timeout>([^<]*)</D:timeout>', r.stdout)
        assert m, f"no <D:timeout> in response: {r.stdout}"
        assert m.group(1) == "Second-0", f"timeout: {m.group(1)}"

    # the expiry, the expiry check and the reported remaining time
    # come from the same clock: a lock expiring "now" is never still
    # held and never reports a second left, even when the LOCK lands
    # right after a second boundary
    def test_dav_004_04(self, env):
        conn = http.client.HTTPConnection(env.http_addr, env.http_port,
                                          timeout=10)
        headers = {
            'Host': f"test1.{env.http_tld}",
            'Timeout': 'Second-0',
            'Content-Type': 'text/xml',
        }
        bad = []
        count = 0
        # span several second boundaries
        end = time.time() + 3.5
        try:
            while time.time() < end:
                conn.request('LOCK', '/dav-timeout-overflow/file4.txt',
                             body=LOCK_BODY, headers=headers)
                resp = conn.getresponse()
                body = resp.read().decode()
                count += 1
                if resp.status != 200:
                    # a lock expiring "now" is still held: 423
                    bad.append(resp.status)
                    continue
                m = re.search(r'<D:timeout>([^<]*)</D:timeout>', body)
                assert m, f"no <D:timeout> in response: {body}"
                if m.group(1) != "Second-0":
                    bad.append(m.group(1))
        finally:
            conn.close()
        assert not bad, \
            f"{len(bad)} of {count} locks: {sorted(set(map(str, bad)))}"
