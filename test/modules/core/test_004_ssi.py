import sys
import pytest
import textwrap

from pyhttpd.conf import HttpdConf

@pytest.mark.skipif(sys.platform == "win32",
                    reason="exec cmd= needs /bin/sh; echo is a cmd.exe builtin, not an executable")
class TestSSIInjection:

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env):
        conf = HttpdConf(env, extras={
            "base": textwrap.dedent(f"""
            <Directory "{env.gen_dir}">
                Options +Includes
                AddType text/html .shtml
                AddOutputFilter INCLUDES .shtml
            </Directory>
            """)
        })
        conf.install()
        assert env.apache_restart() == 0

    def test_ssi_004_01(self, env):
        """
        CVE-2025-58098:
        Server Side Includes must not add query string to #exec cmd=...
        """
        url = env.mkurl("http", "htdocs", "/ssi/exec.shtml?INJECTED")
        r = env.curl_get(url)

        body = r.response["body"].decode("utf-8")
        assert "SSI_OK" in body
        assert "INJECTED" not in body