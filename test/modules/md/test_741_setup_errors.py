# test ACME error responses and their processing
import os

import pytest

from .md_conf import MDConf
from .md_env import MDTestEnv


@pytest.mark.skipif(condition=not MDTestEnv.has_acme_server(),
                    reason="no ACME test server configured")
class TestSetupErrors:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, acme):
        env.APACHE_CONF_SRC = "data/test_auto"
        acme.start(config='default')
        env.check_acme()
        env.clear_store()
        MDConf(env).install()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        env.clear_store()
        self.mcmd = os.path.join(env.test_dir, "../modules/md/http_challenge_foobar.py")
        self.test_domain = env.get_request_domain(request)

    def test_md_741_001(self, env):
        # setup an MD with a MDMessageCmd that make the http-01 challenge file invalid
        # before the ACME server is asked to retrieve it. This will result in
        # an "invalid" domain authorization.
        # The certificate sign-up will be attempted again after 4 seconds and
        # of course fail again.
        # Verify that the error counter for the staging job increments, so
        # that our retry logic goes into proper delayed backoff.
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        conf.add("MDCAChallenges http-01")
        conf.add(f"MDMessageCmd {self.mcmd} {env.store_dir}")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        md = env.await_error(domain, errors=2, timeout=10)
        assert md
        assert md['renewal']['errors'] > 0
