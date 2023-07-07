# test wildcard certifcates
import os

import pytest

from .md_conf import MDConf, MDConf
from .md_env import MDTestEnv


@pytest.mark.skipif(condition=not MDTestEnv.has_acme_server(),
                    reason="no ACME test server configured")
class TestWildcard:

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

    # test case: a wildcard certificate with ACMEv2, no dns-01 supported
    def test_md_720_001(self, env):
        domain = self.test_domain
        
        # generate config with DNS wildcard
        domains = [domain, "*." + domain]
        conf = MDConf(env)
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()

        # restart, check that md is in store
        assert env.apache_restart() == 0
        env.check_md(domains)
        # await drive completion
        md = env.await_error(domain)
        assert md
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'challenge-mismatch'
        #
        env.httpd_error_log.ignore_recent(
            lognos = [
                "AH10056"   # None of offered challenge types
            ],
            matches = [
                r'.*problem\[challenge-mismatch\].*'
            ]
        )

    # test case: a wildcard certificate with ACMEv2, only dns-01 configured, invalid command path
    def test_md_720_002(self, env):
        dns01cmd = os.path.join(env.test_dir, "../modules/md/dns01-not-found.py")

        domain = self.test_domain
        domains = [domain, "*." + domain]
        
        conf = MDConf(env)
        conf.add("MDCAChallenges dns-01")
        conf.add(f"MDChallengeDns01 {dns01cmd}")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()

        # restart, check that md is in store
        assert env.apache_restart() == 0
        env.check_md(domains)
        # await drive completion
        md = env.await_error(domain)
        assert md
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'challenge-setup-failure'
        #
        env.httpd_error_log.ignore_recent(
            lognos = [
                "AH10056"   # None of offered challenge types
            ],
            matches = [
                r'.*problem\[challenge-setup-failure\].*',
                r'.*setup command failed to execute.*'
            ]
        )

    # variation, invalid cmd path, other challenges still get certificate for non-wildcard
    def test_md_720_002b(self, env):
        dns01cmd = os.path.join(env.test_dir, "../modules/md/dns01-not-found.py")
        domain = self.test_domain
        domains = [domain, "xxx." + domain]
        
        conf = MDConf(env)
        conf.add(f"MDChallengeDns01 {dns01cmd}")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()

        # restart, check that md is in store
        assert env.apache_restart() == 0
        env.check_md(domains)
        # await drive completion
        assert env.await_completion([domain])
        env.check_md_complete(domain)
        # check: SSL is running OK
        cert_a = env.get_cert(domain)
        altnames = cert_a.get_san_list()
        for domain in domains:
            assert domain in altnames

    # test case: a wildcard certificate with ACMEv2, only dns-01 configured, invalid command option
    def test_md_720_003(self, env):
        dns01cmd = os.path.join(env.test_dir, "../modules/md/dns01.py fail")
        domain = self.test_domain
        domains = [domain, "*." + domain]
        
        conf = MDConf(env)
        conf.add("MDCAChallenges dns-01")
        conf.add(f"MDChallengeDns01 {dns01cmd}")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()

        # restart, check that md is in store
        assert env.apache_restart() == 0
        env.check_md(domains)
        # await drive completion
        md = env.await_error(domain)
        assert md
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'challenge-setup-failure'
        #
        env.httpd_error_log.ignore_recent(
            lognos = [
                "AH10056"   # None of offered challenge types
            ],
            matches = [
                r'.*problem\[challenge-setup-failure\].*'
            ]
        )

    # test case: a wildcard name certificate with ACMEv2, only dns-01 configured
    def test_md_720_004(self, env):
        dns01cmd = os.path.join(env.test_dir, "../modules/md/dns01.py")
        domain = self.test_domain
        domains = [domain, "*." + domain]
        
        conf = MDConf(env)
        conf.add("MDCAChallenges dns-01")
        conf.add(f"MDChallengeDns01 {dns01cmd}")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()

        # restart, check that md is in store
        assert env.apache_restart() == 0
        env.check_md(domains)
        # await drive completion
        assert env.await_completion([domain])
        env.check_md_complete(domain)
        # check: SSL is running OK
        cert_a = env.get_cert(domain)
        altnames = cert_a.get_san_list()
        for domain in domains:
            assert domain in altnames

    # test case: a wildcard name and 2nd normal vhost, not overlapping
    def test_md_720_005(self, env):
        dns01cmd = os.path.join(env.test_dir, "../modules/md/dns01.py")
        domain = self.test_domain
        domain2 = "www.x" + domain
        domains = [domain, "*." + domain, domain2]
        
        conf = MDConf(env)
        conf.add("MDCAChallenges dns-01")
        conf.add(f"MDChallengeDns01 {dns01cmd}")
        conf.add_md(domains)
        conf.add_vhost(domain2)
        conf.add_vhost(domains)
        conf.install()

        # restart, check that md is in store
        assert env.apache_restart() == 0
        env.check_md(domains)
        # await drive completion
        assert env.await_completion([domain])
        env.check_md_complete(domain)
        # check: SSL is running OK
        cert_a = env.get_cert(domain)
        altnames = cert_a.get_san_list()
        for domain in domains:
            assert domain in altnames

    # test case: a wildcard name and 2nd normal vhost, overlapping
    def test_md_720_006(self, env):
        dns01cmd = os.path.join(env.test_dir, "../modules/md/dns01.py")
        domain = self.test_domain
        dwild = "*." + domain
        domain2 = "www." + domain
        domains = [domain, dwild, domain2]
        
        conf = MDConf(env)
        conf.add("MDCAChallenges dns-01")
        conf.add(f"MDChallengeDns01 {dns01cmd}")
        conf.add_md(domains)
        conf.add_vhost(domain2)
        conf.add_vhost([domain, dwild])
        conf.install()

        # restart, check that md is in store
        assert env.apache_restart() == 0
        env.check_md(domains)
        # await drive completion
        assert env.await_completion([domain])
        env.check_md_complete(domain)
        # check: SSL is running OK
        cert_a = env.get_cert(domain)
        altnames = cert_a.get_san_list()
        for domain in [domain, dwild]:
            assert domain in altnames

    # test case: a MDomain with just a wildcard, see #239
    def test_md_720_007(self, env):
        dns01cmd = os.path.join(env.test_dir, "../modules/md/dns01.py")
        domain = self.test_domain
        dwild = "*." + domain
        wwwdomain = "www." + domain
        domains = [dwild]

        conf = MDConf(env)
        conf.add("MDCAChallenges dns-01")
        conf.add(f"MDChallengeDns01 {dns01cmd}")
        conf.add_md(domains)
        conf.add_vhost(wwwdomain)
        conf.install()

        # restart, check that md is in store
        assert env.apache_restart() == 0
        env.check_md(domains)
        # await drive completion
        assert env.await_completion([wwwdomain])
        env.check_md_complete(dwild)
        # check: SSL is running OK
        cert_a = env.get_cert(wwwdomain)
        altnames = cert_a.get_san_list()
        assert domains == altnames

    # test case: a plain name, only dns-01 configured,
    # http-01 should not be intercepted. See #279
    def test_md_720_008(self, env):
        dns01cmd = os.path.join(env.test_dir, "../modules/md/dns01.py")
        domain = self.test_domain
        domains = [domain]

        conf = MDConf(env)
        conf.add("MDCAChallenges dns-01")
        conf.add(f"MDChallengeDns01 {dns01cmd}")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.add("LogLevel http:trace4")
        conf.install()

        challengedir = os.path.join(env.server_dir, "htdocs/test1/.well-known/acme-challenge")
        env.mkpath(challengedir)
        content = b'not a challenge'
        with open(os.path.join(challengedir, "123456"), "wb") as fd:
            fd.write(content)

        # restart, check that md is in store
        assert env.apache_restart() == 0
        env.check_md(domains)
        # await drive completion
        assert env.await_completion([domain], restart=False)
        # access a fake http-01 challenge on the domain
        r = env.curl_get(f"http://{domain}:{env.http_port}/.well-known/acme-challenge/123456")
        assert r.response['status'] == 200
        assert r.response['body'] == content
        assert env.apache_restart() == 0
        env.check_md_complete(domain)
