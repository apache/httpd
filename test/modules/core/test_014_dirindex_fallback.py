import os

import pytest

from pyhttpd.conf import HttpdConf


class TestDirIndexFallback:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        files = {
            "fallback.txt": "FALLBACK\n",
            # the index is the second DirectoryIndex name
            "second/index.txt": "SECOND INDEX\n",
            # the index is the first DirectoryIndex name
            "first/index.html": "FIRST INDEX\n",
            "noindex/other.txt": "OTHER\n",
        }
        for name, content in files.items():
            path = os.path.join(doc_dir, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(content)

        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": """
            DirectoryIndex index.html index.txt
            FallbackResource /fallback.txt
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def get(self, env, path):
        r = env.curl_get(env.mkurl("http", "test1", path))
        assert r.response, "no response"
        return r.response["status"], r.stdout

    # The DirectoryIndex file that exists is served, even if the ones before
    # it in the list do not and there is a FallbackResource.
    def test_core_014_01(self, env):
        status, body = self.get(env, "/second/")
        assert status == 200
        assert body == "SECOND INDEX\n"

    def test_core_014_02(self, env):
        status, body = self.get(env, "/first/")
        assert status == 200
        assert body == "FIRST INDEX\n"

    # A URL that does not map to anything gets the fallback.
    def test_core_014_03(self, env):
        status, body = self.get(env, "/nothere")
        assert status == 200
        assert body == "FALLBACK\n"

    # So does a directory without any of the DirectoryIndex files.
    def test_core_014_04(self, env):
        status, body = self.get(env, "/noindex/")
        assert status == 200
        assert body == "FALLBACK\n"
