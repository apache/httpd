import os
import shutil
import sys

import pytest

from pyhttpd.conf import HttpdConf


@pytest.mark.skipif(sys.platform == 'win32',
                    reason="mod_ext_filter spawns a Unix command")
class TestFilterByTypeProvider:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        tr = shutil.which("tr")
        if not tr:
            pytest.skip("tr is not installed")
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        for sub in ["bytype", "chain"]:
            d = os.path.join(doc_dir, sub)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "hello.txt"), "w") as f:
                f.write("hello filter\n")

        conf = HttpdConf(env, extras={
            'base': f"""
            ExtFilterDefine upcase mode=output cmd="{tr} a-z A-Z"
            FilterDeclare UPCASE
            FilterProvider UPCASE upcase "%{{CONTENT_TYPE}} = 'text/plain'"
            """,
            f"test1.{env.http_tld}": """
            <Location "/bytype">
                AddOutputFilterByType upcase text/plain
            </Location>
            <Location "/chain">
                SetHandler none
                FilterChain UPCASE
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def get(self, env, path):
        r = env.curl_get(env.mkurl("http", "test1", path))
        assert r.response, "no response"
        return r.response["status"], r.stdout

    # A provider filter installed by AddOutputFilterByType must see its own,
    # unprefixed name in f->frec, not mod_filter's "BYTYPE:" wrapper name,
    # or a provider that looks up its own config by name (like
    # mod_ext_filter) does not find it.
    def test_filters_005_01(self, env):
        status, body = self.get(env, "/bytype/hello.txt")
        assert status == 200
        assert body == "HELLO FILTER\n"

    # The same applies to a provider installed via FilterChain, where
    # mod_filter's wrapper name is the FilterDeclare name, not the
    # provider's.
    def test_filters_005_02(self, env):
        status, body = self.get(env, "/chain/hello.txt")
        assert status == 200
        assert body == "HELLO FILTER\n"
