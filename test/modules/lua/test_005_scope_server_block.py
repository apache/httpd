import pytest

from pyhttpd.conf import HttpdConf


# A <LuaHook...> block is compiled to bytecode when the config is read.
# With "LuaScope server" the VM spec is copied for the per-server VM pool,
# and the copy has to carry the whole bytecode, which contains NUL bytes.
class TestScopeServerBlock:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.require(env.has_shared_module("lua"), "mod_lua not built",
                    dep="mod_lua")

    def configure(self, env, scope):
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
            <Location "/">
                LuaScope {scope}
                <LuaHookFixups fixup>
                function fixup(r)
                    r.headers_out["X-Lua-Fixup"] = "hit"
                    return apache2.DECLINED
                end
                </LuaHookFixups>
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    @pytest.mark.parametrize("scope", ["once", "request", "server 1 1"])
    def test_lua_005_01_block_hook(self, env, scope):
        self.configure(env, scope)
        for _ in range(3):
            r = env.curl_get(env.mkurl("http", "test1", "/index.html"))
            assert r.response["status"] == 200, r.response
            assert r.response["header"].get("x-lua-fixup") == "hit"
