import glob
import os

import pytest

from pyhttpd.conf import HttpdConf


LOCK_BODY = ('<?xml version="1.0" encoding="utf-8"?>'
             '<D:lockinfo xmlns:D="DAV:">'
             '<D:lockscope><D:exclusive/></D:lockscope>'
             '<D:locktype><D:write/></D:locktype>'
             '<D:owner><D:href>test-owner</D:href></D:owner>'
             '</D:lockinfo>')

BOGUS_TOKEN = '<opaquelocktoken:00000000-0000-0000-0000-000000000000>'


class TestDavIfNotLocktoken:
    """A locktoken given under "Not" in the If: header is an assertion
    that the token is not held, and must not count as submitting the
    token for a locked resource."""

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        dav_dir = os.path.join(env.gen_dir, 'dav-ifnot')
        os.makedirs(dav_dir, exist_ok=True)
        for f in glob.glob(os.path.join(env.gen_dir, 'davlock-ifnot*')):
            os.remove(f)
        dav_dir_conf = dav_dir.replace('\\', '/')
        lock_db_conf = os.path.join(env.gen_dir,
                                    'davlock-ifnot').replace('\\', '/')
        conf = HttpdConf(env, extras={
            'base': f"""
        DavLockDB "{lock_db_conf}"
        """,
            f"test1.{env.http_tld}": f"""
        Alias /dav-ifnot "{dav_dir_conf}"
        <Directory "{dav_dir_conf}">
            Dav On
            Require all granted
        </Directory>
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def _url(self, env, name):
        return env.mkurl("http", "test1", f"/dav-ifnot/{name}")

    def _locked(self, env, name):
        """Create and lock a resource, returning its URL and the
        locktoken in Coded-URL form."""
        with open(os.path.join(env.gen_dir, 'dav-ifnot', name), 'w') as fd:
            fd.write('locked')
        url = self._url(env, name)
        r = env.curl_raw(url, options=[
            '-X', 'LOCK',
            '-H', 'Content-Type: text/xml',
            '--data-binary', LOCK_BODY])
        assert r.response["status"] == 200
        return url, r.response["header"]["lock-token"]

    def _put(self, env, url, if_header):
        return env.curl_raw(url, options=[
            '-X', 'PUT',
            '-H', f'If: {if_header}',
            '--data-binary', 'changed'])

    # "Not <token>" in a tagged list for another resource
    def test_dav_006_01_not_token_other_resource(self, env):
        url, token = self._locked(env, 'one.txt')
        other = self._url(env, 'other.txt')
        r = self._put(env, url, f'<{other}> (Not {token})')
        assert r.response["status"] == 423
        env.httpd_error_log.ignore_recent(matches=[r'.*dav:error.*'])

    # As above, where a tagged list for the resource itself also matches
    def test_dav_006_02_not_token_matching_list(self, env):
        url, token = self._locked(env, 'two.txt')
        other = self._url(env, 'other.txt')
        r = self._put(env, url,
                      f'<{url}> (Not {BOGUS_TOKEN}) <{other}> (Not {token})')
        assert r.response["status"] == 423
        env.httpd_error_log.ignore_recent(matches=[r'.*dav:error.*'])

    # The token is still accepted when submitted without "Not",
    # whichever resource the list is tagged for.
    @pytest.mark.parametrize("tag", ['three.txt', 'other.txt'])
    def test_dav_006_03_token_submitted(self, env, tag):
        url, token = self._locked(env, 'three.txt')
        r = self._put(env, url, f'<{self._url(env, tag)}> ({token})')
        assert r.response["status"] == 204
        r = env.curl_raw(url, options=['-X', 'UNLOCK',
                                       '-H', f'Lock-Token: {token}'])
        assert r.response["status"] == 204
