import json.encoder
import os
import re

import pytest

from .md_conf import MDConf
from .md_env import MDTestEnv


@pytest.mark.skipif(condition=not MDTestEnv.has_acme_eab(),
                    reason="ACME test server does not support External Account Binding")
class TestEab:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, acme):
        acme.start(config='eab')
        env.check_acme()
        env.clear_store()
        MDConf(env).install()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        env.clear_store()
        self.test_domain = env.get_request_domain(request)

    def test_md_750_001(self, env):
        # md without EAB configured
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        md = env.await_error(domain)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:externalAccountRequired'

    def test_md_750_002(self, env):
        # md with known EAB KID and non base64 hmac key configured
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        conf.add("MDExternalAccountBinding kid-1 äöüß")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        md = env.await_error(domain)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'apache:eab-hmac-invalid'

    def test_md_750_003(self, env):
        # md with empty EAB KID configured
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        conf.add("MDExternalAccountBinding \" \" bm90IGEgdmFsaWQgaG1hYwo=")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        md = env.await_error(domain)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:unauthorized'

    def test_md_750_004(self, env):
        # md with unknown EAB KID configured
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        conf.add("MDExternalAccountBinding key-x bm90IGEgdmFsaWQgaG1hYwo=")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        md = env.await_error(domain)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:unauthorized'

    def test_md_750_005(self, env):
        # md with known EAB KID but wrong HMAC configured
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        conf.add("MDExternalAccountBinding kid-1 bm90IGEgdmFsaWQgaG1hYwo=")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        md = env.await_error(domain)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:unauthorized'

    def test_md_750_010(self, env):
        # md with correct EAB configured
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        # this is one of the values in conf/pebble-eab.json
        conf.add("MDExternalAccountBinding kid-1 zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion(domains)

    def test_md_750_011(self, env):
        # first one md with EAB, then one without, works only for the first
        # as the second is unable to reuse the account
        domain_a = f"a{self.test_domain}"
        domain_b = f"b{self.test_domain}"
        conf = MDConf(env)
        conf.start_md([domain_a])
        conf.add("MDExternalAccountBinding kid-1 zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W")
        conf.end_md()
        conf.add_vhost(domains=[domain_a])
        conf.add_md([domain_b])
        conf.add_vhost(domains=[domain_b])
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain_a], restart=False)
        md = env.await_error(domain_b)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:externalAccountRequired'

    def test_md_750_012(self, env):
        # first one md without EAB, then one with
        # first one fails, second works
        domain_a = f"a{self.test_domain}"
        domain_b = f"b{self.test_domain}"
        conf = MDConf(env)
        conf.add_md([domain_a])
        conf.add_vhost(domains=[domain_a])
        conf.start_md([domain_b])
        conf.add("MDExternalAccountBinding kid-1 zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W")
        conf.end_md()
        conf.add_vhost(domains=[domain_b])
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain_b], restart=False)
        md = env.await_error(domain_a)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:externalAccountRequired'

    def test_md_750_013(self, env):
        # 2 mds with the same EAB, should one create a single account
        domain_a = f"a{self.test_domain}"
        domain_b = f"b{self.test_domain}"
        conf = MDConf(env)
        conf.start_md([domain_a])
        conf.add("MDExternalAccountBinding kid-1 zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W")
        conf.end_md()
        conf.add_vhost(domains=[domain_a])
        conf.start_md([domain_b])
        conf.add("MDExternalAccountBinding kid-1 zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W")
        conf.end_md()
        conf.add_vhost(domains=[domain_b])
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain_a, domain_b])
        md_a = env.get_md_status(domain_a)
        md_b = env.get_md_status(domain_b)
        assert md_a['ca'] == md_b['ca']

    def test_md_750_014(self, env):
        # md with correct EAB, get cert, change to another correct EAB
        # needs to create a new account
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        conf.add("MDExternalAccountBinding kid-1 zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion(domains)
        md_1 = env.get_md_status(domain)
        conf = MDConf(env)
        # this is another one of the values in conf/pebble-eab.json
        # add a dns name to force renewal
        domains = [domain, f'www.{domain}']
        conf.add("MDExternalAccountBinding kid-2 b10lLJs8l1GPIzsLP0s6pMt8O0XVGnfTaCeROxQM0BIt2XrJMDHJZBM5NuQmQJQH")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion(domains)
        md_2 = env.get_md_status(domain)
        assert md_1['ca'] != md_2['ca']

    def test_md_750_015(self, env):
        # md with correct EAB, get cert, change to no EAB
        # needs to fail
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        conf.add("MDExternalAccountBinding kid-1 zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion(domains)
        conf = MDConf(env)
        # this is another one of the values in conf/pebble-eab.json
        # add a dns name to force renewal
        domains = [domain, f'www.{domain}']
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_error(domain)
        md = env.await_error(domain)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:externalAccountRequired'

    def test_md_750_016(self, env):
        # md with correct EAB, get cert, change to invalid EAB
        # needs to fail
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        conf.add("MDExternalAccountBinding kid-1 zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion(domains)
        conf = MDConf(env)
        # this is another one of the values in conf/pebble-eab.json
        # add a dns name to force renewal
        domains = [domain, f'www.{domain}']
        conf.add("MDExternalAccountBinding kid-invalud blablabalbalbla")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_error(domain)
        md = env.await_error(domain)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:unauthorized'

    def test_md_750_017(self, env):
        # md without EAB explicitly set to none
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        conf.add("MDExternalAccountBinding kid-1 zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W")
        conf.start_md(domains)
        conf.add("MDExternalAccountBinding none")
        conf.end_md()
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        md = env.await_error(domain)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:externalAccountRequired'

    def test_md_750_018(self, env):
        # md with EAB file that does not exist
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        conf.add("MDExternalAccountBinding does-not-exist")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_fail() == 0
        assert re.search(r'.*file not found:', env.apachectl_stderr), env.apachectl_stderr

    def test_md_750_019(self, env):
        # md with EAB file that is not valid JSON
        domain = self.test_domain
        domains = [domain]
        eab_file = os.path.join(env.server_dir, 'eab.json')
        with open(eab_file, 'w') as fd:
            fd.write("something not JSON\n")
        conf = MDConf(env)
        conf.add("MDExternalAccountBinding eab.json")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_fail() == 0
        assert re.search(r'.*error reading JSON file.*', env.apachectl_stderr), env.apachectl_stderr

    def test_md_750_020(self, env):
        # md with EAB file that is JSON, but missind kid
        domain = self.test_domain
        domains = [domain]
        eab_file = os.path.join(env.server_dir, 'eab.json')
        with open(eab_file, 'w') as fd:
            eab = {'something': 1, 'other': 2}
            fd.write(json.encoder.JSONEncoder().encode(eab))
        conf = MDConf(env)
        conf.add("MDExternalAccountBinding eab.json")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_fail() == 0
        assert re.search(r'.*JSON does not contain \'kid\' element.*', env.apachectl_stderr), env.apachectl_stderr

    def test_md_750_021(self, env):
        # md with EAB file that is JSON, but missind hmac
        domain = self.test_domain
        domains = [domain]
        eab_file = os.path.join(env.server_dir, 'eab.json')
        with open(eab_file, 'w') as fd:
            eab = {'kid': 'kid-1', 'other': 2}
            fd.write(json.encoder.JSONEncoder().encode(eab))
        conf = MDConf(env)
        conf.add("MDExternalAccountBinding eab.json")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_fail() == 0
        assert re.search(r'.*JSON does not contain \'hmac\' element.*', env.apachectl_stderr), env.apachectl_stderr

    def test_md_750_022(self, env):
        # md with EAB file that has correct values
        domain = self.test_domain
        domains = [domain]
        eab_file = os.path.join(env.server_dir, 'eab.json')
        with open(eab_file, 'w') as fd:
            eab = {'kid': 'kid-1', 'hmac': 'zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W'}
            fd.write(json.encoder.JSONEncoder().encode(eab))
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        # this is one of the values in conf/pebble-eab.json
        conf.add("MDExternalAccountBinding eab.json")
        conf.add_md(domains)
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion(domains)
