import os
import textwrap

import pytest

from pyhttpd.conf import HttpdConf


# Iterations per case, chosen so that a call which leaves its result
# (or anything else proportional to its input) in a long-lived pool
# grows the child by roughly 64MB or more.
CASES = {
    # 16KB of input per call
    "base64_encode": 4096,
    "base64_decode": 4096,
    "escape": 4096,
    "unescape": 4096,
    "escape_html": 4096,
    "os_escape_path": 4096,
    "escape_logitem": 4096,
    "construct_url": 4096,
    "htpassword": 4096,
    "expr": 4096,
    "regex": 4096,
    "regex_compile": 16384,
    # 2KB of input per call
    "runtime_dir_relative": 32768,
    "ivm_get": 4096,
    "ivm_set": 4096,
    # a fixed-size result per call
    "md5": 2000000,
    "sha1": 2000000,
    "scoreboard_worker": 200000,
    "config": 20000,
    "options": 1000000,
    "allowoverrides": 4000000,
    "headers_in": 2000000,
    "get_direntries": 100000,
    "sendfile": 200000,
    "wspeek": 1000000,
}

# Growth below this is noise: the Lua heap, malloc arenas, and so on.
LIMIT_KB = 16 * 1024


@pytest.mark.skipif(not os.path.exists("/proc/self/status"),
                    reason="needs /proc/self/status")
@pytest.mark.skipif("TEST_ASAN" in os.environ,
                    reason="RSS is not a measure of memory use under ASan")
class TestMemory:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.require(env.has_shared_module("lua"), "mod_lua not built",
                    dep="mod_lua")
        # A fresh child for each request, so that memory one case
        # leaves behind in the allocator cannot hide growth in the next.
        conf = HttpdConf(env, extras={
            'base': textwrap.dedent(f"""
            MaxConnectionsPerChild 1
            LuaScope once
            <Directory "{env.server_docs_dir}/test1/lua">
                SetHandler lua-script
                # Neither All nor None, for r.allowoverrides
                AllowOverride FileInfo
            </Directory>
            """),
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def growth(self, env, case, count):
        url = env.mkurl("http", "test1", f"/lua/mem.lua?{case}&{count}")
        r = env.curl_raw([url], timeout=120)
        assert r.response["status"] == 200, r.response
        return int(r.response["body"])

    def test_lua_002_01_noop(self, env):
        assert self.growth(env, "noop", 1000000) < LIMIT_KB

    @pytest.mark.parametrize("case", CASES.keys())
    def test_lua_002_02_growth(self, env, case):
        growth = self.growth(env, case, CASES[case])
        assert growth < LIMIT_KB, \
            f"r:{case} x {CASES[case]} grew the child by {growth}kB"
