import time
from datetime import timedelta

import pytest

from .conf import TlsTestConf


class TestMD:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = TlsTestConf(env=env, extras={
            'base': "LogLevel md:trace4"
        })
        conf.add_md_vhosts(domains=[env.domain_a, env.domain_b])
        conf.install()
        assert env.apache_restart() == 0

    def test_tls_11_get_a(self, env):
        # do we see the correct json for the domain_a?
        data = env.tls_get_json(env.domain_a, "/index.json")
        assert data == {'domain': env.domain_a}

    def test_tls_11_get_b(self, env):
        # do we see the correct json for the domain_a?
        data = env.tls_get_json(env.domain_b, "/index.json")
        assert data == {'domain': env.domain_b}

    def test_tls_11_get_base(self, env):
        # give the base server domain_a and lookup its index.json
        conf = TlsTestConf(env=env)
        conf.add_md_base(domain=env.domain_a)
        conf.install()
        assert env.apache_restart() == 0
        data = env.tls_get_json(env.domain_a, "/index.json")
        assert data == {'domain': 'localhost'}
