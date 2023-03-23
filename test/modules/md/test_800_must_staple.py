# test mod_md must-staple support
import pytest

from .md_conf import MDConf
from .md_cert_util import MDCertUtil
from .md_env import MDTestEnv


@pytest.mark.skipif(condition=not MDTestEnv.has_acme_server(),
                    reason="no ACME test server configured")
class TestMustStaple:
    domain = None

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, acme):
        acme.start(config='default')
        env.check_acme()
        env.clear_store()
        MDConf(env).install()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        self.domain = env.get_class_domain(self.__class__)

    def configure_httpd(self, env, domain, add_lines=""):
        conf = MDConf(env, admin="admin@" + domain)
        conf.add(add_lines)
        conf.add_md([domain])
        conf.add_vhost(domain)
        conf.install()

    # MD with default, e.g. not staple
    def test_md_800_001(self, env):
        self.configure_httpd(env, self.domain)
        assert env.apache_restart() == 0
        assert env.await_completion([self.domain])
        env.check_md_complete(self.domain)
        cert1 = MDCertUtil(env.store_domain_file(self.domain, 'pubcert.pem'))
        assert not cert1.get_must_staple()

    # MD that should explicitly not staple
    def test_md_800_002(self, env):
        self.configure_httpd(env, self.domain, "MDMustStaple off")
        assert env.apache_restart() == 0
        env.check_md_complete(self.domain)
        cert1 = MDCertUtil(env.store_domain_file(self.domain, 'pubcert.pem'))
        assert not cert1.get_must_staple()
        stat = env.get_ocsp_status(self.domain)
        assert 'ocsp' not in stat or stat['ocsp'] == "no response sent"

    # MD that must staple and toggle off again
    @pytest.mark.skipif(MDTestEnv.lacks_ocsp(), reason="no OCSP responder")
    def test_md_800_003(self, env):
        self.configure_httpd(env, self.domain, "MDMustStaple on")
        assert env.apache_restart() == 0
        assert env.await_completion([self.domain])
        env.check_md_complete(self.domain)
        cert1 = MDCertUtil(env.store_domain_file(self.domain, 'pubcert.pem'))
        assert cert1.get_must_staple()
        self.configure_httpd(env, self.domain, "MDMustStaple off")
        assert env.apache_restart() == 0
        assert env.await_completion([self.domain])
        env.check_md_complete(self.domain)
        cert1 = MDCertUtil(env.store_domain_file(self.domain, 'pubcert.pem'))
        assert not cert1.get_must_staple()

    # MD that must staple
    @pytest.mark.skipif(MDTestEnv.lacks_ocsp(), reason="no OCSP responder")
    @pytest.mark.skipif(MDTestEnv.get_ssl_module() != "mod_ssl", reason="only for mod_ssl")
    def test_md_800_004(self, env):
        # mod_ssl stapling is off, expect no stapling
        stat = env.get_ocsp_status(self.domain)
        assert stat['ocsp'] == "no response sent" 
        # turn mod_ssl stapling on, expect an answer
        self.configure_httpd(env, self.domain, """
            LogLevel ssl:trace2
            SSLUseStapling On
            SSLStaplingCache shmcb:stapling_cache(128000)
            """)
        assert env.apache_restart() == 0
        stat = env.get_ocsp_status(self.domain)
        assert stat['ocsp'] == "successful (0x0)" 
        assert stat['verify'] == "0 (ok)"
