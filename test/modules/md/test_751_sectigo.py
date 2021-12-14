import os
import re
import time

import pytest

from .md_conf import MDConf

# set the environment variables
#   SECTIGO_EAB="$kid $hmac" for
#   SECTIGO_TLD="<your registered dns name>"
# these tests to become active
#

DEMO_ACME = "https://acme.demo.sectigo.com/"
DEMO_TLD = None

EABS = [
    {'kid': '0123', 'hmac': 'abcdef'},
]


def missing_eab():
    global EABS
    if len(EABS) == 1 and 'SECTIGO_EAB' in os.environ:
        m = re.match(r'^\s*(\S+)\s+(\S+)\s*$', os.environ['SECTIGO_EAB'])
        if m:
            EABS.append({'kid': m.group(1), 'hmac': m.group(2)})
    return len(EABS) == 1


def missing_tld():
    global DEMO_TLD
    if 'SECTIGO_TLD' in os.environ:
        DEMO_TLD = os.environ['SECTIGO_TLD']
    return DEMO_TLD is None


@pytest.mark.skipif(condition=missing_tld(), reason="env var SECTIGO_TLD not set")
@pytest.mark.skipif(condition=missing_eab(), reason="env var SECTIGO_EAB not set")
class TestSectigo:

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

    def test_md_751_001(self, env):
        # valid config, expect cert with correct chain
        domain = f"test1.{DEMO_TLD}"
        domains = [domain]
        conf = MDConf(env)
        conf.start_md(domains)
        conf.add(f"MDCertificateAuthority {DEMO_ACME}")
        conf.add("MDCACertificateFile none")
        conf.add(f"MDExternalAccountBinding {EABS[1]['kid']} {EABS[1]['hmac']}")
        conf.end_md()
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_completion(domains)
        r = env.curl_get(f"https://{domain}:{env.https_port}", options=[
            "--cacert", f"{env.test_dir}/data/sectigo-demo-root.pem"
        ])
        assert r.response['status'] == 200

    def test_md_751_002(self, env):
        # without EAB set
        domain = f"test1.{DEMO_TLD}"
        domains = [domain]
        conf = MDConf(env)
        conf.start_md(domains)
        conf.add(f"MDCertificateAuthority {DEMO_ACME}")
        conf.add("MDCACertificateFile none")
        conf.end_md()
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_error(domain)
        md = env.get_md_status(domain)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:externalAccountRequired'

    def test_md_751_003(self, env):
        # with wrong EAB set
        domain = f"test1.{DEMO_TLD}"
        domains = [domain]
        conf = MDConf(env)
        conf.start_md(domains)
        conf.add(f"MDCertificateAuthority {DEMO_ACME}")
        conf.add("MDCACertificateFile none")
        conf.add(f"MDExternalAccountBinding xxxxxx aaaaaaaaaaaaasdddddsdasdsadsadsadasdsadsa")
        conf.end_md()
        conf.add_vhost(domains=domains)
        conf.install()
        assert env.apache_restart() == 0
        assert env.await_error(domain)
        md = env.get_md_status(domain)
        assert md['renewal']['errors'] > 0
        assert md['renewal']['last']['problem'] == 'urn:ietf:params:acme:error:unauthorized'

    def test_md_751_004(self, env):
        # valid config, get cert, add dns name, renew cert
        domain = f"test1.{DEMO_TLD}"
        domain2 = f"test2.{DEMO_TLD}"
        domains = [domain]
        conf = MDConf(env)
        conf.start_md(domains)
        conf.add(f"MDCertificateAuthority {DEMO_ACME}")
        conf.add("MDCACertificateFile none")
        conf.add(f"MDExternalAccountBinding {EABS[1]['kid']} {EABS[1]['hmac']}")
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
        conf.add(f"MDCertificateAuthority {DEMO_ACME}")
        conf.add("MDCACertificateFile none")
        conf.add(f"MDExternalAccountBinding {EABS[1]['kid']} {EABS[1]['hmac']}")
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

    def test_md_751_020(self, env):
        # valid config, get cert, check OCSP status
        domain = f"test1.{DEMO_TLD}"
        domains = [domain]
        conf = MDConf(env)
        conf.add("MDStapling on")
        conf.start_md(domains)
        conf.add(f"""
            MDCertificateAuthority {DEMO_ACME}
            MDCACertificateFile none
            MDExternalAccountBinding {EABS[1]['kid']} {EABS[1]['hmac']}
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
