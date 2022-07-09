import pytest

from .md_env import MDTestEnv
from .md_conf import MDConf


@pytest.mark.skipif(condition=not MDTestEnv.has_acme_server(),
                    reason="no ACME test server configured")
class TestFailover:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, acme):
        acme.start(config='default')
        env.check_acme()
        env.clear_store()
        conf = MDConf(env)
        conf.install()

        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        env.clear_store()
        self.test_domain = env.get_request_domain(request)

    # set 2 ACME certificata authority, valid + invalid
    def test_md_790_001(self, env):
        domain = self.test_domain
        # generate config with one MD
        domains = [domain, "www." + domain]
        conf = MDConf(env)
        conf.add([
            "MDRetryDelay 200ms",  # speed up failovers
        ])
        conf.start_md(domains)
        conf.add([
            f"MDCertificateAuthority {env.acme_url} https://does-not-exist/dir"
        ])
        conf.end_md()
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain])
        env.check_md_complete(domain)

    # set 2 ACME certificata authority, invalid + valid
    def test_md_790_002(self, env):
        domain = self.test_domain
        # generate config with one MD
        domains = [domain, "www." + domain]
        conf = MDConf(env)
        conf.add([
            "MDRetryDelay 100ms",  # speed up failovers
            "MDRetryFailover 2",
        ])
        conf.start_md(domains)
        conf.add([
            f"MDCertificateAuthority https://does-not-exist/dir {env.acme_url} "
        ])
        conf.end_md()
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain])
        env.check_md_complete(domain)

    # set 3 ACME certificata authority, invalid + invalid + valid
    def test_md_790_003(self, env):
        domain = self.test_domain
        # generate config with one MD
        domains = [domain, "www." + domain]
        conf = MDConf(env)
        conf.add([
            "MDRetryDelay 100ms",  # speed up failovers
            "MDRetryFailover 2",
        ])
        conf.start_md(domains)
        conf.add([
            f"MDCertificateAuthority https://does-not-exist/dir https://does-not-either/ "
            f"{env.acme_url} "
        ])
        conf.end_md()
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain])
        env.check_md_complete(domain)
