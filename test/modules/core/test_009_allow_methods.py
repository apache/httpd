import pytest

from pyhttpd.conf import HttpdConf


class TestAllowMethods:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env)
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    # mod_aptest passes the methods named in AP-Test-Allow-Methods to
    # ap_allow_methods() from a fixups hook; the default handler then
    # merges its own and answers OPTIONS with the Allow header.
    def options(self, env, methods=None):
        options = ['-X', 'OPTIONS']
        if methods is not None:
            options.extend(['-H', f'AP-Test-Allow-Methods: {methods}'])
        r = env.curl_get(env.mkurl("http", "test1", "/index.html"),
                         options=options)
        assert r.response, f"no response: {r.stderr}"
        assert r.response["status"] == 200
        return [m.strip() for m in r.response["header"]["allow"].split(',')]

    def test_core_009_01(self, env):
        allow = self.options(env)
        for method in ["GET", "POST", "OPTIONS"]:
            assert method in allow, f"expected {method} in Allow: {allow}"

    def test_core_009_02(self, env):
        allow = self.options(env, "DELETE")
        assert "DELETE" in allow, f"expected DELETE in Allow: {allow}"

    # An extension method reaches make_allow() only through method_list,
    # which is emitted just when the M_INVALID bit is set in method_mask.
    def test_core_009_03(self, env):
        allow = self.options(env, "FROBNICATE")
        assert "FROBNICATE" in allow, f"expected FROBNICATE in Allow: {allow}"

    def test_core_009_04(self, env):
        allow = self.options(env, "DELETE, FROBNICATE")
        for method in ["DELETE", "FROBNICATE"]:
            assert method in allow, f"expected {method} in Allow: {allow}"
