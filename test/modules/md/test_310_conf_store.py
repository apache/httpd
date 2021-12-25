# test mod_md basic configurations
import time

import pytest
import os

from .md_conf import MDConf
from .md_env import MDTestEnv

SEC_PER_DAY = 24 * 60 * 60
MS_PER_DAY = SEC_PER_DAY * 1000
NS_PER_DAY = MS_PER_DAY * 1000


@pytest.mark.skipif(condition=not MDTestEnv.has_a2md(), reason="no a2md available")
@pytest.mark.skipif(condition=not MDTestEnv.has_acme_server(),
                    reason="no ACME test server configured")
class TestConf:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, acme):
        acme.start(config='default')
        env.check_acme()

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        env.clear_store()
        self.test_domain = env.get_request_domain(request)

    # test case: no md definitions in config
    def test_md_310_001(self, env):
        MDConf(env, text="").install()
        assert env.apache_restart() == 0
        r = env.a2md(["list"])
        assert 0 == len(r.json["output"])

    # test case: add md definitions on empty store
    @pytest.mark.parametrize("confline,dns_lists,md_count", [
        ("MDomain testdomain.org www.testdomain.org mail.testdomain.org", 
            [["testdomain.org", "www.testdomain.org", "mail.testdomain.org"]], 1),
        ("""MDomain testdomain.org www.testdomain.org mail.testdomain.org
            MDomain testdomain2.org www.testdomain2.org mail.testdomain2.org""", 
            [["testdomain.org", "www.testdomain.org", "mail.testdomain.org"],
             ["testdomain2.org", "www.testdomain2.org", "mail.testdomain2.org"]], 2)
    ])
    def test_md_310_100(self, env, confline, dns_lists, md_count):
        MDConf(env, text=confline).install()
        assert env.apache_restart() == 0
        for i in range(0, len(dns_lists)):
            env.check_md(dns_lists[i], state=1)

    # test case: add managed domains as separate steps
    def test_md_310_101(self, env):
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        env.check_md(["testdomain.org", "www.testdomain.org", "mail.testdomain.org"], state=1)
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            MDomain testdomain2.org www.testdomain2.org mail.testdomain2.org
            """).install()
        assert env.apache_restart() == 0
        env.check_md(["testdomain.org", "www.testdomain.org", "mail.testdomain.org"], state=1)
        env.check_md(["testdomain2.org", "www.testdomain2.org", "mail.testdomain2.org"], state=1)

    # test case: add dns to existing md
    def test_md_310_102(self, env):
        assert env.a2md(["add", "testdomain.org", "www.testdomain.org"]).exit_code == 0
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        env.check_md(["testdomain.org", "www.testdomain.org", "mail.testdomain.org"], state=1)

    # test case: add new md definition with acme url, acme protocol, acme agreement
    def test_md_310_103(self, env):
        MDConf(env, text="""
            MDCertificateAuthority http://acme.test.org:4000/directory
            MDCertificateProtocol ACME
            MDCertificateAgreement http://acme.test.org:4000/terms/v1

            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """, local_ca=False).install()
        assert env.apache_restart() == 0
        name = "testdomain.org"
        env.check_md([name, "www.testdomain.org", "mail.testdomain.org"], state=1,
                     ca="http://acme.test.org:4000/directory", protocol="ACME",
                     agreement="http://acme.test.org:4000/terms/v1")

    # test case: add to existing md: acme url, acme protocol
    def test_md_310_104(self, env):
        name = "testdomain.org"
        MDConf(env, local_ca=False, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        env.check_md([name, "www.testdomain.org", "mail.testdomain.org"], state=1,
                     ca="https://acme-v02.api.letsencrypt.org/directory", protocol="ACME")
        MDConf(env, local_ca=False, text="""
            MDCertificateAuthority http://acme.test.org:4000/directory
            MDCertificateProtocol ACME
            MDCertificateAgreement http://acme.test.org:4000/terms/v1

            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        env.check_md([name, "www.testdomain.org", "mail.testdomain.org"], state=1,
                     ca="http://acme.test.org:4000/directory", protocol="ACME",
                     agreement="http://acme.test.org:4000/terms/v1")

    # test case: add new md definition with server admin
    def test_md_310_105(self, env):
        MDConf(env, admin="admin@testdomain.org", text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        name = "testdomain.org"
        env.check_md([name, "www.testdomain.org", "mail.testdomain.org"], state=1,
                     contacts=["mailto:admin@testdomain.org"])

    # test case: add to existing md: server admin
    def test_md_310_106(self, env):
        name = "testdomain.org"
        assert env.a2md(["add", name, "www.testdomain.org", "mail.testdomain.org"]).exit_code == 0
        MDConf(env, admin="admin@testdomain.org", text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        env.check_md([name, "www.testdomain.org", "mail.testdomain.org"], state=1,
                     contacts=["mailto:admin@testdomain.org"])

    # test case: assign separate contact info based on VirtualHost
    def test_md_310_107(self, env):
        MDConf(env, admin="", text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            MDomain testdomain2.org www.testdomain2.org mail.testdomain2.org

            <VirtualHost *:12346>
                ServerName testdomain.org
                ServerAlias www.testdomain.org
                ServerAdmin mailto:admin@testdomain.org
            </VirtualHost>

            <VirtualHost *:12346>
                ServerName testdomain2.org
                ServerAlias www.testdomain2.org
                ServerAdmin mailto:admin@testdomain2.org
            </VirtualHost>
            """).install()
        assert env.apache_restart() == 0
        name1 = "testdomain.org"
        name2 = "testdomain2.org"
        env.check_md([name1, "www." + name1, "mail." + name1], state=1, contacts=["mailto:admin@" + name1])
        env.check_md([name2, "www." + name2, "mail." + name2], state=1, contacts=["mailto:admin@" + name2])

    # test case: normalize names - lowercase
    def test_md_310_108(self, env):
        MDConf(env, text="""
            MDomain testdomain.org WWW.testdomain.org MAIL.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        env.check_md(["testdomain.org", "www.testdomain.org", "mail.testdomain.org"], state=1)

    # test case: default drive mode - auto
    def test_md_310_109(self, env):
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['renew-mode'] == 1

    # test case: drive mode manual
    def test_md_310_110(self, env):
        MDConf(env, text="""
            MDRenewMode manual
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['renew-mode'] == 0

    # test case: drive mode auto
    def test_md_310_111(self, env):
        MDConf(env, text="""
            MDRenewMode auto
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['renew-mode'] == 1

    # test case: drive mode always
    def test_md_310_112(self, env):
        MDConf(env, text="""
            MDRenewMode always
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['renew-mode'] == 2

    # test case: renew window - 14 days
    def test_md_310_113a(self, env):
        MDConf(env, text="""
            MDRenewWindow 14d
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['renew-window'] == '14d'

    # test case: renew window - 10 percent
    def test_md_310_113b(self, env):
        MDConf(env, text="""
            MDRenewWindow 10%
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['renew-window'] == '10%'
        
    # test case: ca challenge type - http-01
    def test_md_310_114(self, env):
        MDConf(env, text="""
            MDCAChallenges http-01
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['ca']['challenges'] == ['http-01']

    # test case: ca challenge type - http-01
    def test_md_310_115(self, env):
        MDConf(env, text="""
            MDCAChallenges tls-alpn-01
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['ca']['challenges'] == ['tls-alpn-01']

    # test case: ca challenge type - all
    def test_md_310_116(self, env):
        MDConf(env, text="""
            MDCAChallenges http-01 tls-alpn-01
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['ca']['challenges'] == ['http-01', 'tls-alpn-01']

    # test case: automatically collect md names from vhost config
    def test_md_310_117(self, env):
        conf = MDConf(env, text="""
            MDMember auto
            MDomain testdomain.org
            """)
        conf.add_vhost(port=12346, domains=[
            "testdomain.org", "test.testdomain.org", "mail.testdomain.org",
        ], with_ssl=True)
        conf.install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['domains'] == \
               ['testdomain.org', 'test.testdomain.org', 'mail.testdomain.org']

    # add renew window to existing md
    def test_md_310_118(self, env):
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        MDConf(env, text="""
            MDRenewWindow 14d
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        stat = env.get_md_status("testdomain.org")
        assert stat['renew-window'] == '14d'

    # test case: set RSA key length 2048
    def test_md_310_119(self, env):
        MDConf(env, text="""
            MDPrivateKeys RSA 2048
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['privkey'] == {
            "type": "RSA",
            "bits": 2048
        }

    # test case: set RSA key length 4096
    def test_md_310_120(self, env):
        MDConf(env, text="""
            MDPrivateKeys RSA 4096
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['privkey'] == {
            "type": "RSA",
            "bits": 4096
        }

    # test case: require HTTPS
    def test_md_310_121(self, env):
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            MDRequireHttps temporary
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['require-https'] == "temporary"

    # test case: require OCSP stapling
    def test_md_310_122(self, env):
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            MDMustStaple on
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['must-staple'] is True

    # test case: remove managed domain from config
    def test_md_310_200(self, env):
        dns_list = ["testdomain.org", "www.testdomain.org", "mail.testdomain.org"]
        env.a2md(["add"] + dns_list)
        env.check_md(dns_list, state=1)
        conf = MDConf(env,)
        conf.install()
        assert env.apache_restart() == 0
        # check: md stays in store
        env.check_md(dns_list, state=1)

    # test case: remove alias DNS from managed domain
    def test_md_310_201(self, env):
        dns_list = ["testdomain.org", "test.testdomain.org", "www.testdomain.org", "mail.testdomain.org"]
        env.a2md(["add"] + dns_list)
        env.check_md(dns_list, state=1)
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        # check: DNS has been removed from md in store
        env.check_md(["testdomain.org", "www.testdomain.org", "mail.testdomain.org"], state=1)

    # test case: remove primary name from managed domain
    def test_md_310_202(self, env):
        dns_list = ["name.testdomain.org", "testdomain.org", "www.testdomain.org", "mail.testdomain.org"]
        env.a2md(["add"] + dns_list)
        env.check_md(dns_list, state=1)
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        # check: md overwrite previous name and changes name
        env.check_md(["testdomain.org", "www.testdomain.org", "mail.testdomain.org"],
                     md="testdomain.org", state=1)

    # test case: remove one md, keep another
    def test_md_310_203(self, env):
        dns_list1 = ["greenbytes2.de", "www.greenbytes2.de", "mail.greenbytes2.de"]
        dns_list2 = ["testdomain.org", "www.testdomain.org", "mail.testdomain.org"]
        env.a2md(["add"] + dns_list1)
        env.a2md(["add"] + dns_list2)
        env.check_md(dns_list1, state=1)
        env.check_md(dns_list2, state=1)
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        # all mds stay in store
        env.check_md(dns_list1, state=1)
        env.check_md(dns_list2, state=1)

    # test case: remove ca info from md, should switch over to new defaults
    def test_md_310_204(self, env):
        name = "testdomain.org"
        MDConf(env, local_ca=False, text="""
            MDCertificateAuthority http://acme.test.org:4000/directory
            MDCertificateProtocol ACME
            MDCertificateAgreement http://acme.test.org:4000/terms/v1

            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        # setup: sync with ca info removed
        MDConf(env, local_ca=False, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        env.check_md([name, "www.testdomain.org", "mail.testdomain.org"], state=1,
                     ca="https://acme-v02.api.letsencrypt.org/directory", protocol="ACME")

    # test case: remove server admin from md
    def test_md_310_205(self, env):
        name = "testdomain.org"
        MDConf(env, admin="admin@testdomain.org", text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        # setup: sync with admin info removed
        MDConf(env, admin="", text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        # check: md stays the same with previous admin info
        env.check_md([name, "www.testdomain.org", "mail.testdomain.org"], state=1,
                     contacts=["mailto:admin@testdomain.org"])

    # test case: remove renew window from conf -> fallback to default
    def test_md_310_206(self, env):
        MDConf(env, text="""
            MDRenewWindow 14d
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['renew-window'] == '14d'
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        # check: renew window not set
        assert env.a2md(["list"]).json['output'][0]['renew-window'] == '33%'

    # test case: remove drive mode from conf -> fallback to default (auto)
    @pytest.mark.parametrize("renew_mode,exp_code", [
        ("manual", 0), 
        ("auto", 1), 
        ("always", 2)
    ])
    def test_md_310_207(self, env, renew_mode, exp_code):
        MDConf(env, text="""
            MDRenewMode %s
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """ % renew_mode).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['renew-mode'] == exp_code
        #
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['renew-mode'] == 1

    # test case: remove challenges from conf -> fallback to default (not set)
    def test_md_310_208(self, env):
        MDConf(env, text="""
            MDCAChallenges http-01
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['ca']['challenges'] == ['http-01']
        #
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert 'challenges' not in env.a2md(["list"]).json['output'][0]['ca']

    # test case: specify RSA key
    @pytest.mark.parametrize("key_size", ["2048", "4096"])
    def test_md_310_209(self, env, key_size):
        MDConf(env, text="""
            MDPrivateKeys RSA %s
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """ % key_size).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['privkey']['type'] == "RSA"
        #
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert "privkey" not in env.a2md(["list"]).json['output'][0]

    # test case: require HTTPS
    @pytest.mark.parametrize("mode", ["temporary", "permanent"])
    def test_md_310_210(self, env, mode):
        MDConf(env, text="""
            <MDomainSet testdomain.org>
                MDMember www.testdomain.org mail.testdomain.org
                MDRequireHttps %s
            </MDomainSet>
            """ % mode).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['require-https'] == mode, \
            "Unexpected HTTPS require mode in store. config: {}".format(mode)
        #
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert "require-https" not in env.a2md(["list"]).json['output'][0], \
            "HTTPS require still persisted in store. config: {}".format(mode)

    # test case: require OCSP stapling
    def test_md_310_211(self, env):
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            MDMustStaple on
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['must-staple'] is True
        #
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['must-staple'] is False

    # test case: reorder DNS names in md definition
    def test_md_310_300(self, env):
        dns_list = ["testdomain.org", "mail.testdomain.org", "www.testdomain.org"]
        env.a2md(["add"] + dns_list)
        env.check_md(dns_list, state=1)
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        # check: dns list changes
        env.check_md(["testdomain.org", "www.testdomain.org", "mail.testdomain.org"], state=1)

    # test case: move DNS from one md to another
    def test_md_310_301(self, env):
        env.a2md(["add", "testdomain.org", "www.testdomain.org", "mail.testdomain.org", "mail.testdomain2.org"])
        env.a2md(["add", "testdomain2.org", "www.testdomain2.org"])
        env.check_md(["testdomain.org", "www.testdomain.org",
                      "mail.testdomain.org", "mail.testdomain2.org"], state=1)
        env.check_md(["testdomain2.org", "www.testdomain2.org"], state=1)        
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            MDomain testdomain2.org www.testdomain2.org mail.testdomain2.org
            """).install()
        assert env.apache_restart() == 0
        env.check_md(["testdomain.org", "www.testdomain.org", "mail.testdomain.org"], state=1)
        env.check_md(["testdomain2.org", "www.testdomain2.org", "mail.testdomain2.org"], state=1)

    # test case: change ca info
    def test_md_310_302(self, env):
        name = "testdomain.org"
        MDConf(env, local_ca=False, text="""
            MDCertificateAuthority http://acme.test.org:4000/directory
            MDCertificateProtocol ACME
            MDCertificateAgreement http://acme.test.org:4000/terms/v1

            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        # setup: sync with changed ca info
        MDConf(env, local_ca=False, admin="webmaster@testdomain.org",
                  text="""
            MDCertificateAuthority http://somewhere.com:6666/directory
            MDCertificateProtocol ACME
            MDCertificateAgreement http://somewhere.com:6666/terms/v1

            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        # check: md stays the same with previous ca info
        env.check_md([name, "www.testdomain.org", "mail.testdomain.org"], state=1,
                     ca="http://somewhere.com:6666/directory", protocol="ACME",
                     agreement="http://somewhere.com:6666/terms/v1")

    # test case: change server admin
    def test_md_310_303(self, env):
        name = "testdomain.org"
        MDConf(env, admin="admin@testdomain.org", text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        # setup: sync with changed admin info
        MDConf(env, local_ca=False, admin="webmaster@testdomain.org", text="""
            MDCertificateAuthority http://somewhere.com:6666/directory
            MDCertificateProtocol ACME
            MDCertificateAgreement http://somewhere.com:6666/terms/v1

            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        # check: md stays the same with previous admin info
        env.check_md([name, "www.testdomain.org", "mail.testdomain.org"], state=1,
                     contacts=["mailto:webmaster@testdomain.org"])

    # test case: change drive mode - manual -> auto -> always
    def test_md_310_304(self, env):
        MDConf(env, text="""
            MDRenewMode manual
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['renew-mode'] == 0
        # test case: drive mode auto
        MDConf(env, text="""
            MDRenewMode auto
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['renew-mode'] == 1
        # test case: drive mode always
        MDConf(env, text="""
            MDRenewMode always
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['renew-mode'] == 2

    # test case: change config value for renew window, use various syntax alternatives
    def test_md_310_305(self, env):
        MDConf(env, text="""
            MDRenewWindow 14d
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        md = env.a2md(["list"]).json['output'][0]
        assert md['renew-window'] == '14d'
        MDConf(env, text="""
            MDRenewWindow 10
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        md = env.a2md(["list"]).json['output'][0]
        assert md['renew-window'] == '10d'
        MDConf(env, text="""
            MDRenewWindow 10%
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        md = env.a2md(["list"]).json['output'][0]
        assert md['renew-window'] == '10%'

    # test case: change challenge types - http -> tls-sni -> all
    def test_md_310_306(self, env):
        MDConf(env, text="""
            MDCAChallenges http-01
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['ca']['challenges'] == ['http-01']
        # test case: drive mode auto
        MDConf(env, text="""
            MDCAChallenges tls-alpn-01
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['ca']['challenges'] == ['tls-alpn-01']
        # test case: drive mode always
        MDConf(env, text="""
            MDCAChallenges http-01 tls-alpn-01
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['ca']['challenges'] == ['http-01', 'tls-alpn-01']

    # test case:  RSA key length: 4096 -> 2048 -> 4096
    def test_md_310_307(self, env):
        MDConf(env, text="""
            MDPrivateKeys RSA 4096
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['privkey'] == {
            "type": "RSA",
            "bits": 4096
        }
        MDConf(env, text="""
            MDPrivateKeys RSA 2048
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['privkey'] == {
            "type": "RSA",
            "bits": 2048
        }
        MDConf(env, text="""
            MDPrivateKeys RSA 4096
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['privkey'] == {
            "type": "RSA",
            "bits": 4096
        }

    # test case: change HTTPS require settings on existing md
    def test_md_310_308(self, env):
        # setup: nothing set
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert "require-https" not in env.a2md(["list"]).json['output'][0]
        # test case: temporary redirect
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            MDRequireHttps temporary
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['require-https'] == "temporary"
        # test case: permanent redirect
        MDConf(env, text="""
            <MDomainSet testdomain.org>
                MDMember www.testdomain.org mail.testdomain.org
                MDRequireHttps permanent
            </MDomainSet>
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['require-https'] == "permanent"

    # test case: change OCSP stapling settings on existing md
    def test_md_310_309(self, env):
        # setup: nothing set
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['must-staple'] is False
        # test case: OCSP stapling on
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            MDMustStaple on
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['must-staple'] is True
        # test case: OCSP stapling off
        MDConf(env, text="""
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            MDMustStaple off
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'][0]['must-staple'] is False

    # test case: change renew window parameter
    @pytest.mark.parametrize("window", [
        "0%", "33d", "40%"
    ])
    def test_md_310_310(self, env, window):
        # non-default renewal setting
        domain = self.test_domain
        conf = MDConf(env, admin="admin@" + domain)
        conf.start_md([domain])
        conf.add_drive_mode("manual")
        conf.add_renew_window(window)
        conf.end_md()
        conf.add_vhost(domains=domain)
        conf.install()
        assert env.apache_restart() == 0
        stat = env.get_md_status(domain)
        assert stat["renew-window"] == window

    # test case: add dns name on existing valid md
    def test_md_310_400(self, env):
        # setup: create complete md in store
        domain = self.test_domain
        name = "www." + domain
        assert env.a2md(["add", name, "test1." + domain]).exit_code == 0
        assert env.a2md(["update", name, "contacts", "admin@" + name]).exit_code == 0
        assert env.a2md(["update", name, "agreement", env.acme_tos]).exit_code == 0
        MDConf(env).install()
        assert env.apache_restart() == 0

        # setup: drive it
        r = env.a2md(["-v", "drive", name])
        assert r.exit_code == 0, "drive not successful: {0}".format(r.stderr)
        assert env.a2md(["list", name]).json['output'][0]['state'] == env.MD_S_COMPLETE

        # remove one domain -> status stays COMPLETE
        assert env.a2md(["update", name, "domains", name]).exit_code == 0
        assert env.a2md(["list", name]).json['output'][0]['state'] == env.MD_S_COMPLETE
        
        # add other domain -> status INCOMPLETE
        assert env.a2md(["update", name, "domains", name, "test2." + domain]).exit_code == 0
        assert env.a2md(["list", name]).json['output'][0]['state'] == env.MD_S_INCOMPLETE

    # test case: change ca info
    def test_md_310_401(self, env):
        # setup: create complete md in store
        domain = self.test_domain
        name = "www." + domain
        assert env.a2md(["add", name]).exit_code == 0
        assert env.a2md(["update", name, "contacts", "admin@" + name]).exit_code == 0
        assert env.a2md(["update", name, "agreement", env.acme_tos]).exit_code == 0
        assert env.apache_restart() == 0
        # setup: drive it
        assert env.a2md(["drive", name]).exit_code == 0
        assert env.a2md(["list", name]).json['output'][0]['state'] == env.MD_S_COMPLETE
        # setup: change CA URL
        assert env.a2md(["update", name, "ca", env.acme_url]).exit_code == 0
        # check: state stays COMPLETE
        assert env.a2md(["list", name]).json['output'][0]['state'] == env.MD_S_COMPLETE

    # test case: change the store dir
    def test_md_310_500(self, env):
        MDConf(env, text="""
            MDStoreDir md-other
            MDomain testdomain.org www.testdomain.org mail.testdomain.org
            """).install()
        assert env.apache_restart() == 0
        assert env.a2md(["list"]).json['output'] == []
        env.set_store_dir("md-other")
        env.check_md(["testdomain.org", "www.testdomain.org", "mail.testdomain.org"], state=1)
        env.clear_store()
        env.set_store_dir_default()

    # test case: place an unexpected file into the store, check startup survival, see #218
    def test_md_310_501(self, env):
        # setup: create complete md in store
        domain = self.test_domain
        conf = MDConf(env, admin="admin@" + domain)
        conf.start_md([domain])
        conf.end_md()
        conf.add_vhost(domains=[domain])
        conf.install()
        assert env.apache_restart() == 0
        # add a file at top level
        assert env.await_completion([domain])
        fpath = os.path.join(env.store_domains(), "wrong.com")
        with open(fpath, 'w') as fd:
            fd.write("this does not belong here\n")
        assert env.apache_restart() == 0

    # test case: add external account binding
    def test_md_310_601(self, env):
        domain = self.test_domain
        # directly set
        conf = MDConf(env, admin="admin@" + domain)
        conf.start_md([domain])
        conf.add_drive_mode("manual")
        conf.add("MDExternalAccountBinding k123 hash123")
        conf.end_md()
        conf.add_vhost(domains=domain)
        conf.install()
        assert env.apache_restart() == 0
        stat = env.get_md_status(domain)
        assert stat["eab"] == {'kid': 'k123', 'hmac': '***'}
        # eab inherited
        conf = MDConf(env, admin="admin@" + domain)
        conf.add("MDExternalAccountBinding k456 hash456")
        conf.start_md([domain])
        conf.add_drive_mode("manual")
        conf.end_md()
        conf.add_vhost(domains=domain)
        conf.install()
        assert env.apache_restart() == 0
        stat = env.get_md_status(domain)
        assert stat["eab"] == {'kid': 'k456', 'hmac': '***'}
        # override eab inherited
        conf = MDConf(env, admin="admin@" + domain)
        conf.add("MDExternalAccountBinding k456 hash456")
        conf.start_md([domain])
        conf.add_drive_mode("manual")
        conf.add("MDExternalAccountBinding none")
        conf.end_md()
        conf.add_vhost(domains=domain)
        conf.install()
        assert env.apache_restart() == 0
        stat = env.get_md_status(domain)
        assert "eab" not in stat

