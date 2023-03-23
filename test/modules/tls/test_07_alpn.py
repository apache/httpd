import re
from datetime import timedelta

import pytest

from .conf import TlsTestConf


class TestAlpn:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = TlsTestConf(env=env, extras={
            env.domain_b: "Protocols h2 http/1.1"
        })
        conf.add_tls_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _function_scope(self, env):
        pass

    def _get_protocol(self, output: str):
        for line in output.splitlines():
            m = re.match(r'^\*\s+ALPN[:,] server accepted (to use\s+)?(.*)$', line)
            if m:
                return m.group(2)
        return None

    def test_tls_07_alpn_get_a(self, env):
        # do we see the correct json for the domain_a?
        r = env.tls_get(env.domain_a, "/index.json", options=["-vvvvvv", "--http1.1"])
        assert r.exit_code == 0, r.stderr
        protocol = self._get_protocol(r.stderr)
        assert protocol == "http/1.1", r.stderr

    def test_tls_07_alpn_get_b(self, env):
        # do we see the correct json for the domain_a?
        r = env.tls_get(env.domain_b, "/index.json", options=["-vvvvvv"])
        assert r.exit_code == 0, r.stderr
        protocol = self._get_protocol(r.stderr)
        assert protocol == "h2", r.stderr
