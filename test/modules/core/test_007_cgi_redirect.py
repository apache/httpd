import pytest
import textwrap

from pyhttpd.conf import HttpdConf

class TestCGIRedirectHandler:

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env):
        conf = HttpdConf(env, extras={
            "base": textwrap.dedent(f"""
            <Directory "{env.server_docs_dir}/cgiredir">
                Options +ExecCGI
                <FilesMatch "\\.cgi$">
                    ForceType application/x-httpd-cgi
                </FilesMatch>
            </Directory>
            """)
        })
        conf.install()
        assert env.apache_restart() == 0

    def test_cgi_007_01(self, env):
        """A file with no extension known to mod_mime is not a CGI script."""
        url = env.mkurl("http", "htdocs", "/cgiredir/target")
        r = env.curl_get(url)
        assert r.response["status"] == 200
        body = r.response["body"].decode("utf-8")
        assert "#!/usr/bin/env python3" in body
        assert "EXECUTED-AS-CGI" not in body

    def test_cgi_007_02(self, env):
        """
        A local redirect from a CGI script must not make the redirect
        target inherit the trusted content-type of the script, since
        that would run the target as a CGI script too.
        """
        url = env.mkurl("http", "htdocs", "/cgiredir/redir.cgi?/cgiredir/target")
        r = env.curl_get(url)
        assert r.response["status"] == 200
        body = r.response["body"].decode("utf-8")
        assert "#!/usr/bin/env python3" in body
        assert "EXECUTED-AS-CGI" not in body
