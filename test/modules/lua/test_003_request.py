import os
import textwrap

import pytest

from pyhttpd.conf import HttpdConf


class TestRequest:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.require(env.has_shared_module("lua"), "mod_lua not built",
                    dep="mod_lua")
        conf = HttpdConf(env, extras={
            'base': textwrap.dedent(f"""
            <Directory "{env.server_docs_dir}/test1/lua">
                SetHandler lua-script
                Options +Indexes
                AllowOverride FileInfo
            </Directory>
            <Location "/lua/info.lua">
                LimitRequestBody 5000000000
            </Location>
            """),
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def get(self, env, path):
        r = env.curl_get(env.mkurl("http", "test1", path))
        assert r.response["status"] == 200, r.response
        return r.response["body"].decode().strip()

    # MODLUA_MAX_REG_MATCH (25) capture groups are allowed, and the
    # last of them is returned.
    def test_lua_003_01_regex_max_groups(self, env):
        assert self.get(env, "/lua/regex.lua?24") == "x"
        assert self.get(env, "/lua/regex.lua?25") == "x"

    # The document root and context info outlive the Lua strings they
    # were set from.
    def test_lua_003_02_set_document_root(self, env):
        assert self.get(env, "/lua/docroot.lua?set_document_root") == \
            "x" * 1000 + "/rootN"

    def test_lua_003_03_set_context_info(self, env):
        assert self.get(env, "/lua/docroot.lua?set_context_info") == \
            "x" * 1000 + "/prefixN|" + "x" * 1000 + "/rootN"

    # Request tables read and written through repeated field accesses.
    def test_lua_003_04_fields(self, env):
        r = env.curl_get(env.mkurl("http", "test1", "/lua/fields.lua"))
        assert r.response["status"] == 200, r.response
        assert r.response["header"]["x-lua-notes"] == "12"
        assert r.response["header"]["x-lua-host"].startswith("test1.")
        options, overrides = r.response["body"].decode().strip().split("|")
        assert "Indexes" in options.split()
        assert overrides.split() == ["FileInfo"]

    # Output from r:sendfile() is kept in order with output around it.
    @pytest.mark.parametrize("count", [1, 3])
    def test_lua_003_05_sendfile(self, env, count):
        with open(os.path.join(os.path.dirname(__file__),
                               "htdocs/test1/lua/file.txt")) as f:
            content = f.read()
        assert self.get(env, f"/lua/sendfile.lua?{count}") + "\n" == \
            (content + "--\n") * count

    # A limit over 2^32 is reported in full.
    def test_lua_003_06_limit_req_body(self, env):
        assert self.get(env, "/lua/info.lua?limit_req_body") == "5000000000"

    def test_lua_003_07_mpm_query_unknown(self, env):
        assert self.get(env, "/lua/info.lua?mpm_query") == "nil"

    def test_lua_003_08_scoreboard_worker_range(self, env):
        assert self.get(env, "/lua/info.lua?scoreboard_worker") == "nil"
