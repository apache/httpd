import os
import xml.etree.ElementTree as ET

import pytest

from pyhttpd.conf import HttpdConf


CONTENT_TYPE = 'text/x-test; note="a&b<c>"'

PROPFIND_BODY = ('<?xml version="1.0" encoding="utf-8"?>'
                 '<D:propfind xmlns:D="DAV:">'
                 '<D:prop><D:getcontenttype/></D:prop>'
                 '</D:propfind>')


class TestDavPropfindQuoting:
    """DAV:getcontenttype must be XML-quoted in a PROPFIND response."""

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        dav_dir = os.path.join(env.gen_dir, 'dav-quote')
        os.makedirs(dav_dir, exist_ok=True)
        with open(os.path.join(dav_dir, 'hello.txt'), 'w') as fd:
            fd.write('hello')
        dav_dir_conf = dav_dir.replace('\\', '/')
        lock_db_conf = os.path.join(env.gen_dir,
                                    'davlock-quote').replace('\\', '/')
        conf = HttpdConf(env, extras={
            'base': f"""
        DavLockDB "{lock_db_conf}"
        """,
            f"test1.{env.http_tld}": f"""
        Alias /dav-quote "{dav_dir_conf}"
        <Directory "{dav_dir_conf}">
            Dav On
            Require all granted
            ForceType '{CONTENT_TYPE}'
        </Directory>
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    @pytest.mark.parametrize("body", [PROPFIND_BODY, None])
    def test_dav_007_01_getcontenttype(self, env, body):
        url = env.mkurl("http", "test1", "/dav-quote/hello.txt")
        options = ['-X', 'PROPFIND', '-H', 'Depth: 0']
        if body:
            options += ['-H', 'Content-Type: text/xml',
                        '--data-binary', body]
        r = env.curl_raw(url, options=options)
        assert r.response["status"] == 207
        # fails to parse if the property value is not quoted
        root = ET.fromstring(r.response["body"])
        prop = root.find('.//{DAV:}getcontenttype')
        assert prop is not None
        assert prop.text == CONTENT_TYPE
        assert len(prop) == 0
