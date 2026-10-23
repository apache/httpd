import textwrap

import pytest

from pyhttpd.conf import HttpdConf


class TestSSIBackrefs:

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

    # The captures of a regex in an #if expr are available to a later #set.
    # A group that did not take part in the match is empty, and so is one
    # that the regex does not have.
    def test_core_016_01(self, env):
        url = env.mkurl("http", "htdocs", "/ssi/backref.shtml")
        r = env.curl_get(url)
        assert r.response["status"] == 200
        assert r.response["body"].decode("utf-8").strip() == "[][backref][shtml]"
