import pytest

from pyhttpd.conf import HttpdConf
from .fcgi_faker import FCGIFaker

# ProxyFCGISetEnvIf conditions that evaluate to true without a capturing
# regex match (short-circuited by '||', a regex without captures, a '!~'
# non-match) must expand $N in the replacement to nothing, not to the
# captures of a previous ProxyFCGISetEnvIf entry.
SHORT_CIRCUIT = "req('X-Match') == 'skip' || req('X-Match') =~ m#^(.+)$#"


class TestProxyFCGISetEnvIf:

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        env.require(env.has_shared_module("proxy_fcgi"), "mod_proxy_fcgi not available",
                    dep="mod_proxy_fcgi",
                    detected=f"no mod_proxy_fcgi.so in {env.libexec_dir}")
        faker = FCGIFaker("127.0.0.1", env.http_port2)
        faker.start()
        conf = HttpdConf(env)
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], port=env.http_port)
        conf.add([
            f"ProxyPass / fcgi://127.0.0.1:{env.http_port2}/",
            # a preceding entry with captures, which the next ones must not see
            "ProxyFCGISetEnvIf \"req('X-Prev') =~ m#^(.+)$#\" PREV_CAPTURE \"<$1>\"",
            f"ProxyFCGISetEnvIf \"{SHORT_CIRCUIT}\" X_CAPTURE \"<$1>\"",
            "ProxyFCGISetEnvIf \"req('X-Nocap') =~ m#^.+$#\" NOCAP_CAPTURE \"<$1>\"",
            "ProxyFCGISetEnvIf \"req('X-Neg') !~ m#^(zzz)$#\" NEG_CAPTURE \"<$1>\"",
            "ProxyFCGISetEnvIf \"req('X-Two') =~ m#^(.)(.)#\" TWO_CAPTURE \"<$2$1>\"",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        yield faker
        faker.stop()

    def get_params(self, env, headers):
        options = []
        for k, v in headers.items():
            options += ['-H', f'{k}: {v}']
        r = env.curl_get(env.mkurl("http", "test1", "/"), options=options)
        assert r.response, f"no response: {r.stderr}"
        assert r.response["status"] == 200, r.response
        return r.response["json"]

    def test_proxy_13_01_short_circuit(self, env):
        params = self.get_params(env, {"X-Match": "skip", "X-Prev": "previous"})
        assert params["PREV_CAPTURE"] == "<previous>"
        assert params["X_CAPTURE"] == "<>"

    def test_proxy_13_02_match(self, env):
        params = self.get_params(env, {"X-Match": "foo", "X-Prev": "previous"})
        assert params["PREV_CAPTURE"] == "<previous>"
        assert params["X_CAPTURE"] == "<foo>"

    def test_proxy_13_03_regex_without_captures(self, env):
        params = self.get_params(env, {"X-Nocap": "foo", "X-Prev": "previous"})
        assert params["NOCAP_CAPTURE"] == "<>"

    def test_proxy_13_04_negated_match(self, env):
        params = self.get_params(env, {"X-Neg": "foo", "X-Prev": "previous"})
        assert params["NEG_CAPTURE"] == "<>"

    def test_proxy_13_05_multiple_captures(self, env):
        params = self.get_params(env, {"X-Two": "ab"})
        assert params["TWO_CAPTURE"] == "<ba>"

    def test_proxy_13_06_no_match_unset(self, env):
        # none of the conditions is true: no variables at all
        params = self.get_params(env, {})
        # (NEG_CAPTURE is set: a missing header is "" which does not match)
        for name in ["PREV_CAPTURE", "X_CAPTURE", "NOCAP_CAPTURE",
                     "TWO_CAPTURE"]:
            assert name not in params, params
