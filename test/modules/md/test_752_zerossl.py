import os
import time

import pytest

from .md_conf import MDConf

# set the environment variables
#   ZEROSSL_TLD="<your registered dns name>"
# these tests to become active
#

DEMO_ACME = "https://acme.zerossl.com/v2/DV90"
DEMO_EAB_URL = "http://api.zerossl.com/acme/eab-credentials-email"
DEMO_TLD = None


def missing_tld():
    global DEMO_TLD
    if 'ZEROSSL_TLD' in os.environ:
        DEMO_TLD = os.environ['ZEROSSL_TLD']
    return DEMO_TLD is None


def get_new_eab(env):
    r = env.curl_raw(DEMO_EAB_URL, options=[
        "-d", f"email=admin@zerossl.{DEMO_TLD}"
    ], force_resolve=False)
    assert r.exit_code == 0
    assert r.json
    assert r.json['success'] is True
    assert r.json['eab_kid']
    assert r.json['eab_hmac_key']
    return {'kid': r.json['eab_kid'], 'hmac': r.json['eab_hmac_key']}


@pytest.mark.skipif(condition=missing_tld(), reason="env var ZEROSSL_TLD not set")
class TestZeroSSL:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, acme):
        acme.start(config='eab')
        env.check_acme()
        env.clear_store()
        MDConf(env).install()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _method_scope(self, env, request):
        self.test_domain = env.get_request_domain(request)

    def test_md_752_001(self, env):
        # valid config, expect cert with correct chain
        domain = f"test1.{DEMO_TLD}"
        domains = [domain]
        eab = get_new_eab(env)
        conf = MDConf(env)
        conf.start_md(domains)
        conf.add(f"""
            MDCertificateAuthority {DEMO_ACME}
            MDCertificateAgreement accepted
            MDContactEmail admin@zerossl.{DEMO_TLD}
            MDCACertificateFile none
            MDExternalAccountBinding {eab['kid']} {eab['hmac']}
        """)
        conf.end_md()
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion(domains)
        r = env.curl_get(f"https://{domain}:{env.https_port}", options=[
            "--cacert", f"{env.test_dir}/data/sectigo-demo-root.pem"
        ])
        assert r.response['status'] == 200

    def test_md_752_002(self, env):
        # without EAB set
        domain = f"test1.{DEMO_TLD}"
        domains = [domain]
        conf = MDConf(env)
        conf.start_md(domains)
        conf.add(f"""
            MDCertificateAuthority {DEMO_ACME}
            MDCertificateAgreement accepted
            MDContactEmail admin@zerossl.{DEMO_TLD}
            MDCACertificateFile none
        """)
        conf.end_md()
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_error(domain)
        md = env.get_md_status(domain)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:externalAccountRequired'

    def test_md_752_003(self, env):
        # with wrong EAB set
        domain = f"test1.{DEMO_TLD}"
        domains = [domain]
        conf = MDConf(env)
        conf.start_md(domains)
        conf.add(f"""
            MDCertificateAuthority {DEMO_ACME}
            MDCertificateAgreement accepted
            MDContactEmail admin@zerossl.{DEMO_TLD}
            MDCACertificateFile none
        """)
        conf.add(f"MDExternalAccountBinding YmxhYmxhYmxhCg YmxhYmxhYmxhCg")
        conf.end_md()
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_error(domain)
        md = env.get_md_status(domain)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:malformed'

    def test_md_752_004(self, env):
        # valid config, get cert, add dns name, renew cert
        domain = f"test1.{DEMO_TLD}"
        domain2 = f"test2.{DEMO_TLD}"
        domains = [domain]
        eab = get_new_eab(env)
        conf = MDConf(env)
        conf.start_md(domains)
        conf.add(f"""
            MDCertificateAuthority {DEMO_ACME}
            MDCertificateAgreement accepted
            MDContactEmail admin@zerossl.{DEMO_TLD}
            MDCACertificateFile none
            MDExternalAccountBinding {eab['kid']} {eab['hmac']}
        """)
        conf.end_md()
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion(domains)
        r = env.curl_get(f"https://{domain}:{env.https_port}", options=[
            "--cacert", f"{env.test_dir}/data/sectigo-demo-root.pem"
        ])
        assert r.response['status'] == 200
        r = env.curl_get(f"https://{domain2}:{env.https_port}", options=[
            "--cacert", f"{env.test_dir}/data/sectigo-demo-root.pem"
        ])
        assert r.exit_code != 0
        md1 = env.get_md_status(domain)
        acct1 = md1['ca']['account']
        # add the domain2 to the dns names
        domains = [domain, domain2]
        conf = MDConf(env)
        conf.start_md(domains)
        conf.add(f"""
            MDCertificateAuthority {DEMO_ACME}
            MDCertificateAgreement accepted
            MDContactEmail admin@zerossl.{DEMO_TLD}
            MDCACertificateFile none
            MDExternalAccountBinding {eab['kid']} {eab['hmac']}
        """)
        conf.end_md()
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion(domains)
        r = env.curl_get(f"https://{domain2}:{env.https_port}", options=[
            "--cacert", f"{env.test_dir}/data/sectigo-demo-root.pem"
        ])
        assert r.response['status'] == 200
        md2 = env.get_md_status(domain)
        acct2 = md2['ca']['account']
        assert acct2 == acct1, f"ACME account was not reused: {acct1} became {acct2}"

    def test_md_752_020(self, env):
        # valid config, get cert, check OCSP status
        domain = f"test1.{DEMO_TLD}"
        domains = [domain]
        eab = get_new_eab(env)
        conf = MDConf(env)
        conf.add("MDStapling on")
        conf.start_md(domains)
        conf.add(f"""
            MDCertificateAuthority {DEMO_ACME}
            MDCertificateAgreement accepted
            MDContactEmail admin@zerossl.{DEMO_TLD}
            MDCACertificateFile none
            MDExternalAccountBinding {eab['kid']} {eab['hmac']}
        """)
        conf.end_md()
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion(domains)
        r = env.curl_get(f"https://{domain}:{env.https_port}", options=[
            "--cacert", f"{env.test_dir}/data/sectigo-demo-root.pem"
        ])
        assert r.response['status'] == 200
        time.sleep(1)
        for domain in domains:
            stat = env.await_ocsp_status(domain,
                                         ca_file=f"{env.test_dir}/data/sectigo-demo-root.pem")
            assert stat['ocsp'] == "successful (0x0)"
            assert stat['verify'] == "0 (ok)"
