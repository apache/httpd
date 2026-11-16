import http.client

import pytest

from pyhttpd.conf import HttpdConf


# A LuaOutputFilter/LuaInputFilter whose Lua function never yields: every
# single request it filters gets a fresh coroutine via lua_newthread() on
# the cached VM (LuaScope conn/thread/server), rooted on that VM's own
# stack, that mod_lua never pops back off. Enough requests on the same
# cached VM (here: the same kept-alive connection, for "conn" scope) grow
# that stack without bound, eventually crashing the Lua interpreter.
class TestFilterScopeLeak:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.require(env.has_shared_module("lua"), "mod_lua not built",
                    dep="mod_lua")

    SET_DIRECTIVE = {
        "LuaOutputFilter": "SetOutputFilter",
        "LuaInputFilter": "SetInputFilter",
    }

    def configure(self, env, scope, directive):
        set_directive = self.SET_DIRECTIVE[directive]
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
            LuaScope {scope}
            {directive} noop-filter "{env.server_docs_dir}/test1/lua/filter_noop.lua" filter
            <Location "/">
                {set_directive} noop-filter
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def many_requests_one_connection(self, env, count):
        """*count* requests over a single kept-alive HTTP/1.1 connection,
        so a connection-scoped (or, since they all land on the same
        worker, thread-scoped) cached VM sees every one of them."""
        conn = http.client.HTTPConnection(env.http_addr, env.http_port,
                                          timeout=10)
        try:
            for _ in range(count):
                conn.request("GET", "/lua/file.txt",
                            headers={"Host": f"test1.{env.http_tld}"})
                resp = conn.getresponse()
                assert resp.status == 200, resp.status
                resp.read()
        finally:
            conn.close()

    @pytest.mark.parametrize("scope", ["conn", "thread", "server 1 1"])
    @pytest.mark.parametrize("directive", ["LuaOutputFilter", "LuaInputFilter"])
    def test_lua_006_01_filter_many_requests(self, env, scope, directive):
        self.configure(env, scope, directive)
        self.many_requests_one_connection(env, 500)
