# test mod_md basic configurations

import os

import pytest

from .md_conf import MDConf
from .md_env import MDTestEnv


@pytest.mark.skipif(condition=not MDTestEnv.has_a2md(), reason="no a2md available")
@pytest.mark.skipif(condition=not MDTestEnv.has_acme_server(),
                    reason="no ACME test server configured")
class TestRoundtripv2:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, acme):
        acme.start(config='default')
        env.APACHE_CONF_SRC = "data/test_roundtrip"
        env.clear_store()
        MDConf(env).install()

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        env.check_acme()
        self.test_domain = env.get_request_domain(request)

    # --------- add to store ---------

    def test_md_602_000(self, env):
        # test case: generate config with md -> restart -> drive -> generate config
        # with vhost and ssl -> restart -> check HTTPS access
        domain = self.test_domain
        domains = [domain, "www." + domain]

        # - generate config with one md
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("manual")
        conf.add_md(domains)
        conf.install()
        # - restart, check that md is in store
        assert env.apache_restart() == 0
        env.check_md(domains)
        # - drive
        assert env.a2md(["-v", "drive", domain]).exit_code == 0
        assert env.apache_restart() == 0
        env.check_md_complete(domain)
        # - append vhost to config
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        # check: SSL is running OK
        cert = env.get_cert(domain)
        assert domain in cert.get_san_list()

        # check file system permissions:
        env.check_file_permissions(domain)

    def test_md_602_001(self, env):
        # test case: same as test_600_000, but with two parallel managed domains
        domain_a = "a-" + self.test_domain
        domain_b = "b-" + self.test_domain
        # - generate config with one md
        domains_a = [domain_a, "www." + domain_a]
        domains_b = [domain_b, "www." + domain_b]

        conf = MDConf(env)
        conf.add_drive_mode("manual")
        conf.add_md(domains_a)
        conf.add_md(domains_b)
        conf.install()

        # - restart, check that md is in store
        assert env.apache_restart() == 0
        env.check_md(domains_a)
        env.check_md(domains_b)

        # - drive
        assert env.a2md(["drive", domain_a]).exit_code == 0
        assert env.a2md(["drive", domain_b]).exit_code == 0
        assert env.apache_restart() == 0
        env.check_md_complete(domain_a)
        env.check_md_complete(domain_b)

        # - append vhost to config
        conf.add_vhost(domains_a)
        conf.add_vhost(domains_b)
        conf.install()

        # check: SSL is running OK
        assert env.apache_restart() == 0
        cert_a = env.get_cert(domain_a)
        assert domains_a == cert_a.get_san_list()
        cert_b = env.get_cert(domain_b)
        assert domains_b == cert_b.get_san_list()

    def test_md_602_002(self, env):
        # test case: one md, that covers two vhosts
        domain = self.test_domain
        name_a = "a." + domain
        name_b = "b." + domain
        domains = [domain, name_a, name_b]

        # - generate config with one md
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("manual")
        conf.add_md(domains)
        conf.install()
        
        # - restart, check that md is in store
        assert env.apache_restart() == 0
        env.check_md(domains)

        # - drive
        assert env.a2md(["drive", domain]).exit_code == 0
        assert env.apache_restart() == 0
        env.check_md_complete(domain)

        # - append vhost to config
        conf.add_vhost(name_a, doc_root="htdocs/a")
        conf.add_vhost(name_b, doc_root="htdocs/b")
        conf.install()
        
        # - create docRoot folder
        self._write_res_file(os.path.join(env.server_docs_dir, "a"), "name.txt", name_a)
        self._write_res_file(os.path.join(env.server_docs_dir, "b"), "name.txt", name_b)

        # check: SSL is running OK
        assert env.apache_restart() == 0
        cert_a = env.get_cert(name_a)
        assert name_a in cert_a.get_san_list()
        cert_b = env.get_cert(name_b)
        assert name_b in cert_b.get_san_list()
        assert cert_a.same_serial_as(cert_b)
        assert env.get_content(name_a, "/name.txt") == name_a
        assert env.get_content(name_b, "/name.txt") == name_b

    # --------- _utils_ ---------

    def _write_res_file(self, doc_root, name, content):
        if not os.path.exists(doc_root):
            os.makedirs(doc_root)
        open(os.path.join(doc_root, name), "w").write(content)
