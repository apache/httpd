import os

import pytest
from filelock import Timeout, FileLock

from .md_cert_util import MDCertUtil
from .md_conf import MDConf
from .md_env import MDTestEnv


@pytest.mark.skipif(condition=not MDTestEnv.has_acme_server(),
                    reason="no ACME test server configured")
class TestLocks:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, acme):
        env.APACHE_CONF_SRC = "data/test_auto"
        acme.start(config='default')
        env.check_acme()
        env.clear_store()

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        env.clear_store()
        self.test_domain = env.get_request_domain(request)

    def configure_httpd(self, env, domains, add_lines=""):
        conf = MDConf(env)
        conf.add(add_lines)
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()

    # normal renewal with store locks activated
    def test_md_820_001(self, env):
        domain = self.test_domain
        self.configure_httpd(env, [domain], add_lines=[
            "MDStoreLocks 1s"
        ])
        assert env.apache_restart() == 0
        assert env.await_completion([domain])

    # renewal, with global lock held during restert
    @pytest.mark.skip("does not work in our CI")
    def test_md_820_002(self, env):
        domain = self.test_domain
        self.configure_httpd(env, [domain], add_lines=[
            "MDStoreLocks 1s"
        ])
        assert env.apache_restart() == 0
        assert env.await_completion([domain])
        # we have a cert now, add a dns name to force renewal
        certa = MDCertUtil(env.store_domain_file(domain, 'pubcert.pem'))
        self.configure_httpd(env, [domain, f"x.{domain}"], add_lines=[
            "MDStoreLocks 1s"
        ])
        assert env.apache_restart() == 0
        # await new cert, but do not restart, keeps the cert in staging
        assert env.await_completion([domain], restart=False)
        # obtain global lock and restart
        lockfile = os.path.join(env.store_dir, "store.lock")
        with FileLock(lockfile):
            assert env.apache_restart() == 0
        # lock should have prevented staging from being activated,
        # meaning we will have the same cert
        certb = MDCertUtil(env.store_domain_file(domain, 'pubcert.pem'))
        assert certa.same_serial_as(certb)
        # now restart without lock
        assert env.apache_restart() == 0
        certc = MDCertUtil(env.store_domain_file(domain, 'pubcert.pem'))
        assert not certa.same_serial_as(certc)


