import base64
import hashlib
import os

import pytest

from pyhttpd.conf import HttpdConf

LOCK_BODY = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<D:lockinfo xmlns:D="DAV:">'
    '<D:lockscope><D:exclusive/></D:lockscope>'
    '<D:locktype><D:write/></D:locktype>'
    '</D:lockinfo>'
)


# BZ 69999: mswdv_urlencode() in modules/dav/main/ms_wdv.c percent-encodes
# non-alphanumeric bytes with 'msb > 10'/'lsb > 10' instead of '>= 10', so a
# nibble that is exactly 10 (hex 'A') is encoded as ':' (the next character
# after '9' in '0'+10) instead of 'A'. This function is used by
# mswdv_err_checked_out() to build the X-MSDAVEXT_ERROR response header
# (MS-WDV section 2.2.5.3) sent when a write-locked resource's lock owner
# -- the authenticated username that created the lock -- differs from the
# current requester's own authenticated username. A username containing
# '*' (0x2A, lsb=0xA) is enough to trigger it, with no non-ASCII bytes
# involved. Both requests below authenticate (as two different users): an
# authenticated-vs-anonymous pair does not reach mswdv_urlencode() here,
# because httpd's lazy authentication never even runs when every "Require"
# alternative in effect (including a plain "all granted") can be satisfied
# without it, leaving r->user NULL for both sides instead of mismatched.
class TestMswdvUrlencode:

    DAV_USER = "owner*A"
    DAV_PASSWORD = "ownerpass"
    OTHER_USER = "other"
    OTHER_PASSWORD = "otherpass"

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        dav_dir = os.path.join(env.gen_dir, 'dav-mswdv')
        os.makedirs(dav_dir, exist_ok=True)
        with open(os.path.join(dav_dir, 'file.txt'), 'w') as fd:
            fd.write('hello\n')

        pwfile = os.path.join(env.gen_dir, 'dav-mswdv.passwd')
        with open(pwfile, 'w') as fd:
            for user, password in ((self.DAV_USER, self.DAV_PASSWORD),
                                   (self.OTHER_USER, self.OTHER_PASSWORD)):
                digest = base64.b64encode(
                    hashlib.sha1(password.encode()).digest()).decode()
                fd.write(f"{user}:{{SHA}}{digest}\n")

        conf = HttpdConf(env, extras={
            'base': f"""
        DavLockDB "{env.gen_dir}/davlock-mswdv"
        """,
            f"test1.{env.http_tld}": f"""
        Alias /dav-mswdv "{dav_dir}"
        <Directory "{dav_dir}">
            Dav On
            DAVmsExt WDV
            AuthType Basic
            AuthName "dav-mswdv"
            AuthBasicProvider file
            AuthUserFile "{pwfile}"
            Require valid-user
        </Directory>
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def test_dav_004_01(self, env):
        url = env.mkurl("https", "test1", "/dav-mswdv/file.txt")

        # authenticated LOCK: lock->auth_user becomes "owner*A".
        r = env.curl_raw(url, options=[
            '-X', 'LOCK', '-u', f'{self.DAV_USER}:{self.DAV_PASSWORD}',
            '-H', 'Content-Type: text/xml', '--data-binary', LOCK_BODY])
        assert r.response["status"] == 200, r.response

        # a different authenticated user hits the same, now write-locked,
        # resource: check_locked_by_other() sees a lock owner that does
        # not match r->user, and sets X-MSDAVEXT_ERROR via the buggy
        # mswdv_urlencode() before the request fails on the lock conflict.
        r = env.curl_raw(url, options=[
            '-X', 'PUT', '-u', f'{self.OTHER_USER}:{self.OTHER_PASSWORD}',
            '--data-binary', 'new content'])
        assert r.response["status"] == 423, r.response
        err_hdr = r.response["header"].get("x-msdavext_error")
        assert err_hdr, f"no X-MSDAVEXT_ERROR header in {r.response['header']}"
        # correctly encoded: "owner%2AA" (the '*' in "owner*A" as %2A);
        # the bug produces "owner%2:A" instead.
        assert "%2A" in err_hdr, f"X-MSDAVEXT_ERROR: {err_hdr}"
        assert "%2:" not in err_hdr, f"X-MSDAVEXT_ERROR: {err_hdr}"
