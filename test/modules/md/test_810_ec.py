# tests with elliptic curve keys and certificates
import logging

import pytest

from .md_conf import MDConf
from .md_env import MDTestEnv


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

    def set_get_pkeys(self, env, domain, pkeys, conf=None):
        domains = [domain]
        if conf is None:
            conf = MDConf(env)
            conf.add("MDPrivateKeys {0}".format(" ".join([p['spec'] for p in pkeys])))
            conf.add_md(domains)
            conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion([domain])

    def check_pkeys(self, env, domain, pkeys):
        # check that files for all types have been created
        for p in [p for p in pkeys if len(p['spec'])]:
            env.check_md_complete(domain, p['spec'])
        # check that openssl client sees the cert with given keylength for cipher
        env.verify_cert_key_lenghts(domain, pkeys)
    
    def set_get_check_pkeys(self, env, domain, pkeys, conf=None):
        self.set_get_pkeys(env, domain, pkeys, conf=conf)
        self.check_pkeys(env, domain, pkeys)
        
    # one EC key, no RSA
    def test_md_810_001(self, env):
        domain = self.test_domain
        self.set_get_check_pkeys(env, domain, [
            {'spec': "secp256r1", 'ciphers': "ECDSA", 'keylen': 256},
            {'spec': "", 'ciphers': "RSA", 'keylen': 0},
        ])

    # set EC key type override on MD and get certificate
    def test_md_810_002(self, env):
        domain = self.test_domain
        # generate config with one MD
        domains = [domain]
        conf = MDConf(env)
        conf.add("MDPrivateKeys secp256r1")
        conf.start_md(domains)
        conf.add("    MDPrivateKeys secp384r1")
        conf.end_md()
        conf.add_vhost(domains)
        self.set_get_check_pkeys(env, domain, [
            {'spec': "secp384r1", 'ciphers': "ECDSA", 'keylen': 384},
            {'spec': "", 'ciphers': "RSA", 'keylen': 0},
        ])

    # set two key spec, ec before rsa
    def test_md_810_003a(self, env):
        domain = self.test_domain
        self.set_get_check_pkeys(env, domain, [
            {'spec': "P-256", 'ciphers': "ECDSA", 'keylen': 256},
            {'spec': "RSA 3072", 'ciphers': "ECDHE-RSA-CHACHA20-POLY1305", 'keylen': 3072},
        ])

    # set two key spec, rsa before ec
    def test_md_810_003b(self, env):
        domain = self.test_domain
        self.set_get_check_pkeys(env, domain, [
            {'spec': "RSA 3072", 'ciphers': "ECDHE-RSA-CHACHA20-POLY1305", 'keylen': 3072},
            {'spec': "secp384r1", 'ciphers': "ECDSA", 'keylen': 384},
        ])

    # use a curve unsupported by LE
    # only works with mod_ssl as rustls refuses to load such a weak key
    @pytest.mark.skipif(MDTestEnv.get_ssl_module() != "mod_ssl", reason="only for mod_ssl")
    @pytest.mark.skipif(MDTestEnv.get_acme_server() != 'boulder', reason="only boulder rejects this")
    def test_md_810_004(self, env):
        domain = self.test_domain
        # generate config with one MD
        domains = [domain]
        conf = MDConf(env)
        conf.add("MDPrivateKeys secp192r1")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        md = env.await_error(domain)
        assert md
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:malformed'

    # set three key specs
    def test_md_810_005(self, env):
        domain = self.test_domain
        # behaviour differences, mod_ssl selects the strongest suitable,
        # mod_tls selects the first suitable
        ec_key_len = 384 if env.ssl_module == "mod_ssl" else 256
        self.set_get_check_pkeys(env, domain, [
            {'spec': "secp256r1", 'ciphers': "ECDSA", 'keylen': ec_key_len},
            {'spec': "RSA 4096", 'ciphers': "ECDHE-RSA-CHACHA20-POLY1305", 'keylen': 4096},
            {'spec': "P-384", 'ciphers': "ECDSA", 'keylen': ec_key_len},
        ])

    # set three key specs
    def test_md_810_006(self, env):
        domain = self.test_domain
        self.set_get_check_pkeys(env, domain, [
            {'spec': "rsa2048", 'ciphers': "ECDHE-RSA-CHACHA20-POLY1305", 'keylen': 2048},
            {'spec': "secp256r1", 'ciphers': "ECDSA", 'keylen': 256},
        ])

    # start with one pkey and add another one
    def test_md_810_007(self, env):
        domain = self.test_domain
        domains = [domain]
        conf = MDConf(env)
        conf.add("MDPrivateKeys rsa3072")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion(domains)
        conf = MDConf(env)
        conf.add("MDPrivateKeys rsa3072 secp384r1")
        conf.add_md(domains)
        conf.add_vhost(domains)
        conf.install()
        assert env.apache_restart() == 0
        mds = env.get_md_status(domain, via_domain=domain, use_https=True)
        assert 'renew' in mds and mds['renew'] is True, f"{mds}"
        assert env.await_completion(domains)
        self.check_pkeys(env, domain, [
            {'spec': "rsa3072", 'ciphers': "ECDHE-RSA-CHACHA20-POLY1305", 'keylen': 3072},
            {'spec': "secp384r1", 'ciphers': "ECDSA", 'keylen': 384},
        ])

