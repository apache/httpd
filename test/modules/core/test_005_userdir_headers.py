import os
import re
import pytest

from pyhttpd.conf import HttpdConf

class TestUserdirHeaders:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):

        userdir_base = os.path.join(env.server_dir, "htdocs", "userdir")

        conf = HttpdConf(env, extras={
            'base': f"""
        UserDir "{userdir_base}/*/public_html"
 
        <Directory "{userdir_base}/*/public_html">
            AllowOverride FileInfo
            Options +ExecCGI
            SetHandler cgi-script
        </Directory>
        """
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def test_core_005_01_requestheader_note_rejected(self, env):
        url = env.mkurl("http", "test1", "/~testuser/cgi-bin/test.cgi")
        r = env.curl_get(url)

        # Check error log for the rejection message
        re_rejection = re.compile(r".*RequestHeader does not support the 'note' action.*")

        directive_rejected = False
        try:
            directive_rejected = env.httpd_error_log.scan_recent(re_rejection)
        except TimeoutError:
            pass

        assert directive_rejected, \
            "RequestHeader note directive was not rejected"
