import os
import time

import pytest

from pyhttpd.conf import HttpdConf
from pyhttpd.env import HttpdTestEnv
from .md_cert_util import MDCertUtil
from .md_env import MDTestEnv
from .md_conf import MDConf


@pytest.mark.skipif(condition=not MDTestEnv.has_acme_server(),
                    reason="no ACME test server configured")
class TestAutov2:

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

    def _write_res_file(self, doc_root, name, content):
        if not os.path.exists(doc_root):
            os.makedirs(doc_root)
        open(os.path.join(doc_root, name), "w").write(content)

    # create a MD not used in any virtual host, auto drive should NOT pick it up
    def test_md_702_001(self, env):
        domain = self.test_domain
        # generate config with one MD
        domains = [domain, "www." + domain]
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("auto")
        conf.add_md(domains)
        conf.install()
        #
        # restart, check that MD is synched to store
        assert env.apache_restart() == 0
        env.check_md(domains)
        stat = env.get_md_status(domain)
        assert stat["watched"] == 0
        #
        # add vhost for MD, restart should drive it
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain])
        env.check_md_complete(domain)
        stat = env.get_md_status(domain)
        assert stat["watched"] == 1
        cert = env.get_cert(domain)
        assert domain in cert.get_san_list()
        #
        # challenges should have been removed
        # file system needs to have correct permissions
        env.check_dir_empty(env.store_challenges())
        env.check_file_permissions(domain)

    # test case: same as test_702_001, but with two parallel managed domains
    def test_md_702_002(self, env):
        domain = self.test_domain
        domain_a = "a-" + domain
        domain_b = "b-" + domain
        #        
        # generate config with two MDs
        domains_a = [domain_a, "www." + domain_a]
        domains_b = [domain_b, "www." + domain_b]
        conf = MDConf(env)
        conf.add_drive_mode("auto")
        conf.add_md(domains_a)
        conf.add_md(domains_b)
        conf.add_vhost(domains_a)
        conf.add_vhost(domains_b)
        conf.install()
        #
        # restart, check that md is in store
        assert env.apache_restart() == 0
        env.check_md(domains_a)
        env.check_md(domains_b)
        #
        # await drive completion, do not restart
        assert env.await_completion([domain_a, domain_b], restart=False)
        # staged certificates are now visible on the status resources
        status = env.get_md_status(domain_a)
        assert 'renewal' in status
        assert 'cert' in status['renewal']
        assert 'rsa' in status['renewal']['cert']
        assert 'sha256-fingerprint' in status['renewal']['cert']['rsa']
        # check the non-staged status
        assert status['state'] == 1
        assert status['state-descr'] == "certificate(rsa) is missing"

        # restart and activate
        assert env.apache_restart() == 0
        # check: SSL is running OK
        cert_a = env.get_cert(domain_a)
        assert domains_a == cert_a.get_san_list()
        cert_b = env.get_cert(domain_b)
        assert domains_b == cert_b.get_san_list()
        # check that we created only one account
        md_a = env.get_md_status(domain_a)
        md_b = env.get_md_status(domain_b)
        assert md_a['ca'] == md_b['ca']

    # test case: one MD, that covers two vhosts
    def test_md_702_003(self, env):
        domain = self.test_domain
        name_a = "test-a." + domain
        name_b = "test-b." + domain
        domains = [domain, name_a, name_b]
        #
        # generate 1 MD and 2 vhosts
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_md(domains)
        conf.add_vhost(name_a, doc_root="htdocs/a")
        conf.add_vhost(name_b, doc_root="htdocs/b")
        conf.install()
        #
        # create docRoot folder
        self._write_res_file(os.path.join(env.server_docs_dir, "a"), "name.txt", name_a)
        self._write_res_file(os.path.join(env.server_docs_dir, "b"), "name.txt", name_b)
        #
        # restart (-> drive), check that MD was synched and completes
        assert env.apache_restart() == 0
        env.check_md(domains)
        assert env.await_completion([domain])
        md = env.check_md_complete(domain)
        assert md['ca']['url'], f"URL of CA used not set in md: {md}"
        #
        # check: SSL is running OK
        cert_a = env.get_cert(name_a)
        assert name_a in cert_a.get_san_list()
        cert_b = env.get_cert(name_b)
        assert name_b in cert_b.get_san_list()
        assert cert_a.same_serial_as(cert_b)
        #
        assert env.get_content(name_a, "/name.txt") == name_a
        assert env.get_content(name_b, "/name.txt") == name_b

    # test case: drive with using single challenge type explicitly
    @pytest.mark.parametrize("challenge_type", [
        "tls-alpn-01", "http-01",
    ])
    def test_md_702_004(self, env, challenge_type):
        domain = self.test_domain
        domains = [domain, "www." + domain]
        #
        # generate 1 MD and 1 vhost
        conf = MDConf(env, admin="admin@" + domain)
        conf.add("Protocols http/1.1 acme-tls/1")
        conf.add_drive_mode("auto")
        conf.add(f"MDCAChallenges {challenge_type}")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        #
        # restart (-> drive), check that MD was synched and completes
        assert env.apache_restart() == 0
        env.check_md(domains)
        assert env.await_completion([domain])
        env.check_md_complete(domain)
        #        
        # check SSL running OK
        cert = env.get_cert(domain)
        assert domain in cert.get_san_list()

    # test case: drive_mode manual, check that server starts, but requests to domain are 503'd
    def test_md_702_005(self, env):
        domain = self.test_domain
        name_a = "test-a." + domain
        domains = [domain, name_a]
        #
        # generate 1 MD and 1 vhost
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("manual")
        conf.add_md(domains)
        conf.add_vhost(name_a, doc_root="htdocs/a")
        conf.install()
        #
        # create docRoot folder
        self._write_res_file(os.path.join(env.server_docs_dir, "a"), "name.txt", name_a)
        #
        # restart, check that md is in store
        assert env.apache_restart() == 0
        env.check_md(domains)
        #        
        # check: that request to domains give 503 Service Unavailable
        cert1 = env.get_cert(name_a)
        assert name_a in cert1.get_san_list()
        assert env.get_http_status(name_a, "/name.txt") == 503
        #
        # check temporary cert from server
        cert2 = MDCertUtil(env.path_fallback_cert(domain))
        assert cert1.same_serial_as(cert2), \
            "Unexpected temporary certificate on vhost %s. Expected cn: %s , "\
            "but found cn: %s" % (name_a, cert2.get_cn(), cert1.get_cn())

    # test case: drive MD with only invalid challenges, domains should stay 503'd
    def test_md_702_006(self, env):
        domain = self.test_domain
        name_a = "test-a." + domain
        domains = [domain, name_a]
        #
        # generate 1 MD, 1 vhost
        conf = MDConf(env, admin="admin@" + domain)
        conf.add("MDCAChallenges invalid-01 invalid-02")
        conf.add_md(domains)
        conf.add_vhost(name_a, doc_root="htdocs/a")
        conf.install()
        #
        # create docRoot folder
        self._write_res_file(os.path.join(env.server_docs_dir, "a"), "name.txt", name_a)
        #
        # restart, check that md is in store
        assert env.apache_restart() == 0
        env.check_md(domains)
        # await drive completion
        md = env.await_error(domain)
        assert md
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'challenge-mismatch'
        assert 'account' not in md['ca']
        #
        # check: that request to domains give 503 Service Unavailable
        cert = env.get_cert(name_a)
        assert name_a in cert.get_san_list()
        assert env.get_http_status(name_a, "/name.txt") == 503

    # Specify a non-working http proxy
    def test_md_702_008(self, env):
        domain = self.test_domain
        domains = [domain]
        #
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("always")
        conf.add("MDHttpProxy http://localhost:1")
        conf.add_md(domains)
        conf.install()
        #
        # - restart (-> drive)
        assert env.apache_restart() == 0
        # await drive completion
        md = env.await_error(domain)
        assert md
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['status-description'] == 'Connection refused'
        assert 'account' not in md['ca']

    # Specify a valid http proxy
    def test_md_702_008a(self, env):
        domain = self.test_domain
        domains = [domain]
        #
        conf = MDConf(env, admin=f"admin@{domain}", proxy=True)
        conf.add_drive_mode("always")
        conf.add(f"MDHttpProxy http://localhost:{env.proxy_port}")
        conf.add_md(domains)
        conf.install()
        #
        # - restart (-> drive), check that md is in store
        assert env.apache_restart() == 0
        assert env.await_completion([domain])
        assert env.apache_restart() == 0
        env.check_md_complete(domain)

    # Force cert renewal due to critical remaining valid duration
    # Assert that new cert activation is delayed
    def test_md_702_009(self, env):
        domain = self.test_domain
        domains = [domain]
        #
        # prepare md
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("auto")
        conf.add_renew_window("10d")
        conf.add_md(domains)
        conf.add_vhost(domain)
        conf.install()
        #
        # restart (-> drive), check that md+cert is in store, TLS is up
        assert env.apache_restart() == 0
        assert env.await_completion([domain])
        env.check_md_complete(domain)
        cert1 = MDCertUtil(env.store_domain_file(domain, 'pubcert.pem'))
        # compare with what md reports as status
        stat = env.get_certificate_status(domain)
        assert cert1.same_serial_as(stat['rsa']['serial'])
        #
        # create self-signed cert, with critical remaining valid duration -> drive again
        env.create_self_signed_cert([domain], {"notBefore": -120, "notAfter": 2}, serial=7029)
        cert3 = MDCertUtil(env.store_domain_file(domain, 'pubcert.pem'))
        assert cert3.same_serial_as('1B75')
        assert env.apache_restart() == 0
        stat = env.get_certificate_status(domain)
        assert cert3.same_serial_as(stat['rsa']['serial'])
        #
        # cert should renew and be different afterwards
        assert env.await_completion([domain], must_renew=True)
        stat = env.get_certificate_status(domain)
        assert not cert3.same_serial_as(stat['rsa']['serial'])
        
    # test case: drive with an unsupported challenge due to port availability 
    def test_md_702_010(self, env):
        domain = self.test_domain
        domains = [domain, "www." + domain]
        #
        # generate 1 MD and 1 vhost, map port 80 to where the server does not listen
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("auto")
        conf.add("MDPortMap 80:99")        
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        md = env.await_error(domain)
        assert md["renewal"]["errors"] > 0
        #
        # now the same with a 80 mapped to a supported port 
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_drive_mode("auto")
        conf.add("MDCAChallenges http-01")
        conf.add("MDPortMap 80:%s" % env.http_port)
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        env.check_md(domains)
        assert env.await_completion([domain])

    def test_md_702_011(self, env):
        domain = self.test_domain
        domains = [domain, "www." + domain]
        #
        # generate 1 MD and 1 vhost, map port 443 to where the server does not listen
        conf = MDConf(env, admin="admin@" + domain)
        conf.add("Protocols http/1.1 acme-tls/1")
        conf.add_drive_mode("auto")
        conf.add("MDPortMap https:99 http:99")        
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        md = env.await_error(domain)
        assert md["renewal"]["errors"] > 0
        #
        # now the same with a 443 mapped to a supported port 
        conf = MDConf(env, admin="admin@" + domain)
        conf.add("Protocols http/1.1 acme-tls/1")
        conf.add_drive_mode("auto")
        conf.add("MDCAChallenges tls-alpn-01")
        conf.add("MDPortMap https:%s" % env.https_port)
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        env.check_md(domains)
        assert env.await_completion([domain])

    # test case: one MD with several dns names. sign up. remove the *first* name
    # in the MD. restart. should find and keep the existing MD.
    # See: https://github.com/icing/mod_md/issues/68
    def test_md_702_030(self, env):
        domain = self.test_domain
        name_x = "test-x." + domain
        name_a = "test-a." + domain
        name_b = "test-b." + domain
        domains = [name_x, name_a, name_b]
        #
        # generate 1 MD and 2 vhosts
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_md(domains)
        conf.add_vhost(name_a)
        conf.add_vhost(name_b)
        conf.install()
        #
        # restart (-> drive), check that MD was synched and completes
        assert env.apache_restart() == 0
        env.check_md(domains)
        assert env.await_completion([name_x])
        env.check_md_complete(name_x)
        #
        # check: SSL is running OK
        cert_a = env.get_cert(name_a)
        assert name_a in cert_a.get_san_list()
        cert_b = env.get_cert(name_b)
        assert name_b in cert_b.get_san_list()
        assert cert_a.same_serial_as(cert_b)
        #        
        # change MD by removing 1st name
        new_list = [name_a, name_b]
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_md(new_list)
        conf.add_vhost(name_a)
        conf.add_vhost(name_b)
        conf.install()
        # restart, check that host still works and kept the cert
        assert env.apache_restart() == 0
        env.check_md(new_list)
        status = env.get_certificate_status(name_a)
        assert cert_a.same_serial_as(status['rsa']['serial'])

    # test case: Same as 7030, but remove *and* add another at the same time.
    # restart. should find and keep the existing MD and renew for additional name.
    # See: https://github.com/icing/mod_md/issues/68
    def test_md_702_031(self, env):
        domain = self.test_domain
        name_x = "test-x." + domain
        name_a = "test-a." + domain
        name_b = "test-b." + domain
        name_c = "test-c." + domain
        domains = [name_x, name_a, name_b]
        #
        # generate 1 MD and 2 vhosts
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_md(domains)
        conf.add_vhost(name_a)
        conf.add_vhost(name_b)
        conf.install()
        #
        # restart (-> drive), check that MD was synched and completes
        assert env.apache_restart() == 0
        env.check_md(domains)
        assert env.await_completion([name_x])
        env.check_md_complete(name_x)
        #
        # check: SSL is running OK
        cert_a = env.get_cert(name_a)
        assert name_a in cert_a.get_san_list()
        cert_b = env.get_cert(name_b)
        assert name_b in cert_b.get_san_list()
        assert cert_a.same_serial_as(cert_b)
        #        
        # change MD by removing 1st name and adding another
        new_list = [name_a, name_b, name_c]
        conf = MDConf(env, admin="admin@" + domain)
        conf.add_md(new_list)
        conf.add_vhost(name_a)
        conf.add_vhost(name_b)
        conf.install()
        # restart, check that host still works and have new cert
        assert env.apache_restart() == 0
        env.check_md(new_list)
        assert env.await_completion([name_a])
        #
        cert_a2 = env.get_cert(name_a)
        assert name_a in cert_a2.get_san_list()
        assert not cert_a.same_serial_as(cert_a2)

    # test case: create two MDs, move them into one
    # see: <https://bz.apache.org/bugzilla/show_bug.cgi?id=62572>
    def test_md_702_032(self, env):
        domain = self.test_domain
        name1 = "server1." + domain
        name2 = "server2.b" + domain  # need a separate TLD to avoid rate limites
        #
        # generate 2 MDs and 2 vhosts
        conf = MDConf(env, admin="admin@" + domain)
        conf.add("MDMembers auto")
        conf.add_md([name1])
        conf.add_md([name2])
        conf.add_vhost(name1)
        conf.add_vhost(name2)
        conf.install()
        #
        # restart (-> drive), check that MD was synched and completes
        assert env.apache_restart() == 0
        env.check_md([name1])
        env.check_md([name2])
        assert env.await_completion([name1, name2])
        env.check_md_complete(name2)
        #
        # check: SSL is running OK
        cert1 = env.get_cert(name1)
        assert name1 in cert1.get_san_list()
        cert2 = env.get_cert(name2)
        assert name2 in cert2.get_san_list()
        #        
        # remove second md and vhost, add name2 to vhost1
        conf = MDConf(env, admin="admin@" + domain)
        conf.add("MDMembers auto")
        conf.add_md([name1])
        conf.add_vhost([name1, name2])
        conf.install()
        assert env.apache_restart() == 0
        env.check_md([name1, name2])
        assert env.await_completion([name1])
        #
        cert1b = env.get_cert(name1)
        assert name1 in cert1b.get_san_list()
        assert name2 in cert1b.get_san_list()
        assert not cert1.same_serial_as(cert1b)

    # test case: test "tls-alpn-01" challenge handling
    def test_md_702_040(self, env):
        domain = self.test_domain
        domains = [domain, "www." + domain]
        #
        # generate 1 MD and 1 vhost
        conf = MDConf(env, admin="admin@" + domain)
        conf.add("LogLevel core:debug")
        conf.add("Protocols http/1.1 acme-tls/1")
        conf.add_drive_mode("auto")
        conf.add("MDCAChallenges tls-alpn-01")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        #
        # restart (-> drive), check that MD was synched and completes
        assert env.apache_restart() == 0
        env.check_md(domains)
        # check that acme-tls/1 is available for all domains
        stat = env.get_md_status(domain)
        assert stat["proto"]["acme-tls/1"] == domains
        assert env.await_completion([domain])
        env.check_md_complete(domain)
        #        
        # check SSL running OK
        cert = env.get_cert(domain)
        assert domain in cert.get_san_list()

    # test case: test "tls-alpn-01" without enabling 'acme-tls/1' challenge protocol
    def test_md_702_041(self, env):
        domain = self.test_domain
        domains = [domain, "www." + domain]
        #
        # generate 1 MD and 1 vhost
        conf = MDConf(env, admin="admin@" + domain)
        conf.add("LogLevel core:debug")
        conf.add_drive_mode("auto")
        conf.add("MDCAChallenges tls-alpn-01")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        #
        # restart (-> drive), check that MD job shows errors 
        # and that missing proto is detected
        assert env.apache_restart() == 0
        env.check_md(domains)
        # check that acme-tls/1 is available for none of the domains
        stat = env.get_md_status(domain)
        assert stat["proto"]["acme-tls/1"] == []

    # test case: 2.4.40 mod_ssl stumbles over a SSLCertificateChainFile when installing
    # a fallback certificate
    @pytest.mark.skipif(HttpdTestEnv.get_ssl_module() != "mod_ssl", reason="only for mod_ssl")
    def test_md_702_042(self, env):
        domain = self.test_domain
        dns_list = [domain]
        conf = MDConf(env, admin="admin@" + domain)
        conf.add("LogLevel core:debug")
        cred = env.get_credentials_for_name(f"test1.{env.http_tld}")[0]
        conf.add(f"SSLCertificateChainFile {cred.cert_file}")
        conf.add_drive_mode("auto")
        conf.add_md(dns_list)
        conf.add_vhost(dns_list)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain])

    # test case: test "tls-alpn-01" without enabling 'acme-tls/1' challenge protocol
    # and fallback "http-01" configured, see https://github.com/icing/mod_md/issues/255
    def test_md_702_043(self, env):
        domain = self.test_domain
        domains = [domain, "www." + domain]
        #
        # generate 1 MD and 1 vhost
        conf = MDConf(env, admin="admin@" + domain)
        conf.add("LogLevel core:debug")
        conf.add_drive_mode("auto")
        conf.add("MDPortMap 80:%s" % env.http_port)
        conf.add("MDCAChallenges tls-alpn-01 http-01")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        #
        # restart (-> drive), check that MD job shows errors
        # and that missing proto is detected
        assert env.apache_restart() == 0
        env.check_md(domains)
        # check that acme-tls/1 is available for none of the domains
        stat = env.get_md_status(domain)
        assert stat["proto"]["acme-tls/1"] == []
        # but make sure it completes nevertheless
        assert env.await_completion([domain])

    # test case: drive with using single challenge type explicitly
    # and make sure that dns names not mapped to a VirtualHost also work
    @pytest.mark.parametrize("challenge_type", [
        "tls-alpn-01"  # , "http-01",
    ])
    def test_md_702_044(self, env, challenge_type):
        domain = self.test_domain
        md_domains = [domain, "mail." + domain]
        domains = [domain]
        #
        # generate 1 MD and 1 vhost
        conf = MDConf(env, admin="admin@" + domain)
        conf.add("Protocols http/1.1 acme-tls/1")
        conf.add_drive_mode("auto")
        conf.add(f"MDCAChallenges {challenge_type}")
        conf.add_md(md_domains)
        conf.add_vhost(domains)
        conf.install()
        #
        # restart (-> drive), check that MD was synched and completes
        assert env.apache_restart() == 0
        env.check_md(md_domains)
        assert env.await_completion([domain])
        env.check_md_complete(domain)
        #
        # check SSL running OK
        cert = env.get_cert(domain)
        assert md_domains[0] in cert.get_san_list()
        assert md_domains[1] in cert.get_san_list()

    # Make a setup using the base server. It will use http-01 challenge.
    def test_md_702_050(self, env):
        domain = self.test_domain
        conf = MDConf(env, admin=f"admin@{domain}")
        conf.add(f"""
            MDBaseServer on
            ServerName {domain}
            """)
        conf.add_md([domain])
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain])

    # Make a setup using the base server without http:, will fail.
    def test_md_702_051(self, env):
        domain = self.test_domain
        conf = MDConf(env, admin=f"admin@{domain}")
        conf.add(f"""
            MDBaseServer on
            MDPortMap http:-
            ServerName {domain}
            """)
        conf.add_md([domain])
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_error(domain)

    # Make a setup using the base server without http:, but with acme-tls/1, should work.
    def test_md_702_052(self, env):
        domain = self.test_domain
        conf = MDConf(env, std_vhosts=False, admin=f"admin@{domain}")
        conf.add([
            "MDBaseServer on",
            "MDPortMap http:-",
            "Protocols h2 http/1.1 acme-tls/1",
            f"ServerName {domain}",
            "<IfModule ssl_module>",
            "  SSLEngine on",
            "</IfModule>",
            "<IfModule tls_module>",
            f"  TLSEngine {env.https_port}",
            "</IfModule>",
        ])
        conf.add_md([domain])
        conf.install()
        assert env.apache_restart() == 0
        stat = env.get_md_status(domain, via_domain=env.http_addr, use_https=False)
        assert stat["proto"]["acme-tls/1"] == [domain]
        assert env.await_completion([domain], via_domain=env.http_addr, use_https=False)

    # Test a domain name longer than 64 chars, but components < 64, see #227
    # Background: DNS has an official limit of 253 ASCII chars and components must be
    # of length [1, 63].
    # However the CN in a certificate is restricted too, see
    # <https://github.com/letsencrypt/boulder/issues/2093>.
    @pytest.mark.skipif(MDTestEnv.is_pebble(), reason="pebble differs here from boulder")
    @pytest.mark.parametrize("challenge_type", [
        "tls-alpn-01", "http-01"
    ])
    def test_md_702_060(self, env, challenge_type):
        domain = self.test_domain
        # use only too long names, this is expected to fail:
        # see <https://github.com/jetstack/cert-manager/issues/1462>
        long_domain = ("x" * (65 - len(domain))) + domain
        domains = [long_domain, "www." + long_domain]
        conf = MDConf(env, admin="admin@" + domain)
        conf.add("Protocols http/1.1 acme-tls/1")
        conf.add_drive_mode("auto")
        conf.add(f"MDCAChallenges {challenge_type}")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        env.check_md(domains)
        assert env.await_error(long_domain)
        # add a short domain to the SAN list, the CA should now use that one
        # and issue a cert.
        long_domain = ("y" * (65 - len(domain))) + domain
        domains = [long_domain, "www." + long_domain, "xxx." + domain]
        conf = MDConf(env, admin="admin@" + domain)
        conf.add("Protocols http/1.1 acme-tls/1")
        conf.add_drive_mode("auto")
        conf.add(f"MDCAChallenges {challenge_type}")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([long_domain])
        env.check_md_complete(long_domain)
        #
        # check SSL running OK
        cert = env.get_cert(long_domain)
        assert long_domain in cert.get_san_list()

    # test case: fourth level domain
    def test_md_702_070(self, env):
        domain = self.test_domain
        name_a = "one.test." + domain
        name_b = "two.test." + domain
        domains = [name_a, name_b]
        #
        # generate 1 MD and 2 vhosts
        conf = MDConf(env)
        conf.add_admin("admin@" + domain)
        conf.add_md(domains)
        conf.add_vhost(name_a)
        conf.install()
        #
        # restart (-> drive), check that MD was synched and completes
        assert env.apache_restart() == 0
        assert env.await_completion(domains)
        env.check_md_complete(domains[0])

    # test case: fifth level domain
    def test_md_702_071(self, env):
        domain = self.test_domain
        name_a = "one.more.test." + domain
        name_b = "two.more.test." + domain
        domains = [name_a, name_b]
        #
        # generate 1 MD and 2 vhosts
        conf = MDConf(env)
        conf.add_admin("admin@" + domain)
        conf.add_md(domains)
        conf.add_vhost(name_a)
        conf.install()
        #
        # restart (-> drive), check that MD was synched and completes
        assert env.apache_restart() == 0
        assert env.await_completion(domains)
        env.check_md_complete(domains[0])

