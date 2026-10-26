import base64
import hashlib
import os
import uuid

import pytest

from pyhttpd.conf import HttpdConf

# The MS-WDV support reports the owner of a lock in the X-MSDAVEXT_ERROR
# response header, percent-encoded. The owner is the authenticated user name.
DAV_DOC_CHECKED_OUT = 0x0009000E

# One user name with every non-alphanumeric ASCII character that may be part
# of a user name (no ':' and no control characters), and with UTF-8 sequences
# that contain every hex digit in both positions of a byte, one to four bytes
# long.
ASCII_PUNCT = ''.join(c for c in map(chr, range(0x21, 0x7f))
                      if not c.isalnum() and c != ':')
UTF8_ALL = (''.join(chr(c) for c in range(0x80, 0x100))
            + '߿ࠀ�\U0001f600')
ALL_NIBBLES = 'u' + ASCII_PUNCT + UTF8_ALL

OWNERS = [
    'alice',                    # nothing to escape
    'dot.user',                 # escaped, no 'A' digit
    'star*user',                # 0x2A, low digit A
    'café',                # C3 A9, signed char
    'ªº',             # C2 AA C2 BA, both digits A, B
    ALL_NIBBLES,
]


def expected_header(owner: str) -> str:
    msg = b'Resource already locked by ' + owner.encode('utf-8')
    enc = ''.join(chr(c) if chr(c).isalnum() and c < 0x80 else f'%{c:02X}'
                  for c in msg)
    return f'{DAV_DOC_CHECKED_OUT}; {enc}'


def basic(user: str) -> str:
    cred = base64.b64encode(user.encode('utf-8') + b':pw').decode('ascii')
    return f'Authorization: Basic {cred}'


class TestMsWdvUrlencode:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        dav_dir = os.path.join(env.gen_dir, 'dav')
        os.makedirs(dav_dir, exist_ok=True)
        sha = '{SHA}' + base64.b64encode(
            hashlib.sha1(b'pw').digest()).decode('ascii')
        users = os.path.join(env.gen_dir, 'mswdv.htpasswd')
        with open(users, 'w', encoding='utf-8') as fd:
            for user in ['bob'] + OWNERS:
                fd.write(f'{user}:{sha}\n')
        conf = HttpdConf(env, extras={
            'base': f"""
        DavLockDB "{env.gen_dir}/davlock"
        """,
            f"test1.{env.http_tld}": f"""
        Alias /dav "{dav_dir}"
        <Directory "{dav_dir}">
            Dav On
            DAVMSext WDV
            AuthType Basic
            AuthName "dav"
            AuthBasicProvider file
            AuthUserFile "{users}"
            Require valid-user
        </Directory>
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0
        # locks outlive a test run, use names that are new every time
        TestMsWdvUrlencode.run = uuid.uuid4().hex[:12]
        TestMsWdvUrlencode.dav_dir = dav_dir

    def lock(self, env, user, path):
        body = os.path.join(env.gen_dir, 'lockinfo.xml')
        with open(body, 'w') as fd:
            fd.write('<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
                     '<D:lockscope><D:exclusive/></D:lockscope>'
                     '<D:locktype><D:write/></D:locktype></D:lockinfo>')
        return env.curl_raw(env.mkurl("https", "test1", path), options=[
            '-X', 'LOCK', '-H', 'Content-Type: text/xml', '-H', basic(user),
            '--data-binary', f'@{body}'])

    def delete_as_bob(self, env, path):
        # DELETE is checked for a lock of another user like PUT, and has no
        # request body that the server could leave unread when it refuses
        # the request, which resets the connection on Windows
        r = env.curl_raw(env.mkurl("https", "test1", path), options=[
            '-X', 'DELETE', '-H', basic('bob')])
        # the refused request is logged at error level
        env.httpd_error_log.ignore_recent(
            matches=[r'.*This resource is locked and an "If:" header',
                     r'.*Could not DELETE .* failed precondition'])
        return r

    # the lock owner is encoded in the error header of another user's request
    @pytest.mark.parametrize("n", range(len(OWNERS)))
    def test_dav_002_01(self, env, n):
        owner = OWNERS[n]
        name = f"{self.run}-owner{n}.txt"
        path = f"/dav/{name}"
        # the resource has to exist, DELETE does not find a new locked name
        with open(os.path.join(self.dav_dir, name), 'w') as fd:
            fd.write('data\n')
        r = self.lock(env, owner, path)
        assert r.response["status"] == 200, f"{r}"
        r = self.delete_as_bob(env, path)
        assert r.response, f"no response: {r}"
        assert r.response["status"] == 423
        assert r.response["header"]["x-msdavext_error"] \
               == expected_header(owner)
