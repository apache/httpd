# test mod_md cleanups and sanitation

import os

import pytest

from .md_conf import MDConf
from .md_env import MDTestEnv


@pytest.mark.skipif(condition=not MDTestEnv.has_acme_server(),
                    reason="no ACME test server configured")
class TestCleanups:

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
        self.test_domain = env.get_request_domain(request)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    def test_md_910_01(self, env):
        # generate a simple MD
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        conf.add_drive_mode("manual")
        conf.add_md(domains)
        conf.add_vhost(domain)
        conf.install()

        # create valid/invalid challenges subdirs
        challenges_dir = env.store_challenges()
        dirs_before = ["aaa", "bbb", domain, "zzz"]
        for name in dirs_before:
            os.makedirs(os.path.join(challenges_dir, name))

        assert env.apache_restart() == 0
        # the one we use is still there
        assert os.path.isdir(os.path.join(challenges_dir, domain))
        # and the others are gone
        missing_after = ["aaa", "bbb", "zzz"]
        for name in missing_after:
            assert not os.path.exists(os.path.join(challenges_dir, name))
