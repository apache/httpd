import os
import pytest

from pyhttpd.conf import HttpdConf


class TestPropdbNsLimit:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        dav_dir = os.path.join(env.gen_dir, 'dav')
        os.makedirs(dav_dir, exist_ok=True)
        with open(os.path.join(dav_dir, 'file.txt'), 'w') as fd:
            fd.write('hello\n')
        conf = HttpdConf(env, extras={
            'base': f"""
        DavLockDB "{env.gen_dir}/davlock"
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

    @staticmethod
    def _propertyupdate(nspaces: int, prefix: str) -> str:
        # every xmlns declaration in a PROPPATCH body is recorded in the
        # resource's property database, whether or not it is used
        decls = ''.join(f' xmlns:{prefix}{i}="urn:{prefix}{i}"'
                        for i in range(nspaces))
        return ('<?xml version="1.0"?>'
                f'<D:propertyupdate xmlns:D="DAV:"{decls}>'
                f'<D:set><D:prop><{prefix}0:p>v</{prefix}0:p></D:prop></D:set>'
                '</D:propertyupdate>')

    def _proppatch(self, env, body: str):
        fpath = os.path.join(env.gen_dir, 'proppatch.xml')
        with open(fpath, 'w') as fd:
            fd.write(body)
        url = env.mkurl("https", "test1", "/dav/file.txt")
        return env.curl_raw(url, options=[
            '-X', 'PROPPATCH', '-H', 'Content-Type: text/xml',
            '--data-binary', f'@{fpath}'])

    # a modest number of distinct namespaces is accepted and stored
    def test_dav_001_01(self, env):
        r = self._proppatch(env, self._propertyupdate(100, 'a'))
        assert r.response["status"] == 207
        assert 'HTTP/1.1 200' in r.stdout
        assert 'HTTP/1.1 413' not in r.stdout

    # declaring more distinct namespaces than one property database will
    # record must be refused with 413 rather than accepted, and the resource
    # must remain usable afterwards
    def test_dav_001_02(self, env):
        r = self._proppatch(env, self._propertyupdate(2049, 'b'))
        # the refusal is logged at error level, and writing back the
        # oversized namespace table on close fails with a warning
        env.httpd_error_log.ignore_recent(
            lognos=['AH00577'],
            matches=[r'.*Too many distinct namespaces'])
        assert r.response["status"] == 207
        assert 'HTTP/1.1 413' in r.stdout
        url = env.mkurl("https", "test1", "/dav/file.txt")
        r = env.curl_raw(url, options=['-X', 'PROPFIND', '-H', 'Depth: 0'])
        assert r.response["status"] == 207
